# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Test.Matrix do
    @moduledoc """
    A policy matrix test: every actor against every resource and action, checked for
    consistency and compared with a readable snapshot (needs `ecto`).

        defmodule MyApp.AuthzMatrixTest do
          use Warden.Test.Matrix,
            authorizer: MyApp.Authz,
            repo: MyApp.Repo,
            snapshot: "test/authz/matrix.snapshot"

          actor :owner, &Fixtures.owner/1
          actor :guest, &Fixtures.guest/1
          actor :webhook, &Fixtures.team_webhook/1

          resource :issue_public_team, &Fixtures.issue(&1, team: :public)
          resource :issue_private_team, &Fixtures.issue(&1, team: :private)
        end

    The module is an `ExUnit.Case` with one test, `"policy matrix"`, tagged
    `:warden_matrix`. For every actor, every resource and every action of the resource's
    policy it:

      * asserts that the answers agree (`Warden.Test.assert_policy_consistent/4`), and
        fails naming the cell when they do not;
      * records the cell as allowed or denied;
      * records the fields `Warden.redact/3` changes, when the authorizer has a field
        policy for the struct and the actor may take an action on it.

    Then it compares the matrix with the snapshot file and fails with the changed cells
    only. The snapshot holds fixture names, policy modules and field names, never row
    data or subjects. `mix warden.matrix` prints the table, and `mix warden.matrix
    --update` rewrites the snapshot.

    Every policy in the authorizer's `policies:` needs at least one resource, else the
    test fails naming the policy. A resource whose struct has no policy fails too.

    ## Options

      * `:authorizer` (required) - the authorizer.
      * `:repo` (required) - the repo the fixtures write to, for the sandbox and scopes.
      * `:snapshot` (required) - the path of the snapshot file, relative to the project.
      * `:sandbox` - `true` (default) checks out `Ecto.Adapters.SQL.Sandbox` for the
        test; `false` when your own setup does.
      * `:async` - passed to `ExUnit.Case` (default `false`).

    ## Fixtures

    `actor name, fun` and `resource name, fun` take a function of the ExUnit context.
    An actor fixture returns an actor (`Warden.actor/2`, `Warden.system_actor/2`,
    `Warden.on_behalf_of/3`) or a context map; a resource fixture returns a persisted
    struct. All fixtures are built in one setup, after the module's own `setup` blocks,
    in the order they are declared, and each gets the context with the fixtures built
    before it under `:warden_fixtures` (`%{name => value}`), so a guest can join the
    workspace of an earlier resource. The built matrix is in the context as
    `:warden_matrix`, for `Warden.Test.Absinthe.assert_matrix_matches/2` in a test of
    your own.
    """

    alias ExUnit.Callbacks
    alias Warden.{Fields, Policy}
    alias Warden.Policy.Dispatch
    alias Warden.Test.Matrix.Snapshot

    defstruct [:authorizer, :repo, :snapshot, actors: [], resources: []]

    @type t :: %__MODULE__{
            authorizer: module,
            repo: module,
            snapshot: String.t(),
            actors: [{atom, term}],
            resources: [{atom, struct}]
          }

    @option_keys [:authorizer, :repo, :snapshot, :sandbox, :async]
    @mode_variable "WARDEN_MATRIX"

    defmacro __using__(opts) do
      env = __CALLER__
      {opts, _binding} = Code.eval_quoted(opts, [], env)
      options = validate!(opts, env)
      Module.register_attribute(env.module, :warden_matrix_fixtures, accumulate: true)

      quote do
        # Before `use ExUnit.Case`, so the generated setup and test exist when ExUnit's own
        # `@before_compile` collects them.
        @before_compile Warden.Test.Matrix

        use ExUnit.Case, async: unquote(options.async)

        import Warden.Test.Matrix, only: [actor: 2, resource: 2]

        @warden_matrix_options unquote(Macro.escape(options))

        setup context do
          unquote(__MODULE__).__sandbox__(@warden_matrix_options, context)
        end
      end
    end

    @doc "Declares an actor fixture: `fun` gets the ExUnit context and returns an actor or a context map."
    defmacro actor(name, fun), do: fixture(:actor, name, fun, __CALLER__)

    @doc "Declares a resource fixture: `fun` gets the ExUnit context and returns a persisted struct."
    defmacro resource(name, fun), do: fixture(:resource, name, fun, __CALLER__)

    @doc false
    defmacro __before_compile__(env) do
      fixtures = env.module |> Module.get_attribute(:warden_matrix_fixtures) |> Enum.reverse()

      duplicated =
        for {kind, names} <- Enum.group_by(fixtures, &elem(&1, 0), &elem(&1, 1)),
            name <- Enum.uniq(names -- Enum.uniq(names)),
            do: "#{kind} #{inspect(name)} is declared twice"

      if duplicated != [] do
        raise CompileError,
          file: env.file,
          line: env.line,
          description: Enum.join(duplicated, "; ")
      end

      quote do
        # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def __warden_matrix__(:fixtures), do: unquote(Macro.escape(fixtures))

        setup context do
          unquote(__MODULE__).__setup__(__MODULE__, @warden_matrix_options, context)
        end

        @tag :warden_matrix
        test "policy matrix", %{warden_matrix: matrix} do
          unquote(__MODULE__).run!(matrix)
        end
      end
    end

    defp fixture(kind, name_ast, fun_ast, env) do
      {name, _binding} = Code.eval_quoted(name_ast, [], env)

      if not is_atom(name) do
        raise CompileError,
          file: env.file,
          line: env.line,
          description: "a #{kind} name must be an atom"
      end

      function = :"__warden_matrix_#{kind}_#{name}__"
      location = "#{Path.relative_to_cwd(env.file)}:#{env.line}"
      Module.put_attribute(env.module, :warden_matrix_fixtures, {kind, name, function, location})

      # At the declaration's line, so a stacktrace through the fixture points there.
      quote line: env.line do
        # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def unquote(function)(context), do: unquote(fun_ast).(context)
      end
    end

    defp validate!(opts, env) do
      errors =
        case Keyword.keys(opts) -- @option_keys do
          [] -> []
          unknown -> ["unknown options: #{inspect(unknown)}"]
        end

      errors =
        errors ++
          for {key, check} <- [authorizer: &is_atom/1, repo: &is_atom/1, snapshot: &is_binary/1],
              not (Keyword.has_key?(opts, key) and check.(opts[key]) and opts[key] != nil),
              do: "`#{inspect(key)}` is required"

      if errors != [] do
        description = "invalid Warden.Test.Matrix options: " <> Enum.join(errors, "; ")
        raise CompileError, file: env.file, line: env.line, description: description
      end

      %{
        authorizer: opts[:authorizer],
        repo: opts[:repo],
        snapshot: opts[:snapshot],
        sandbox: Keyword.get(opts, :sandbox, true),
        async: Keyword.get(opts, :async, false)
      }
    end

    # Checks the sandbox out for the test, before the module's own setup blocks.
    # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
    @doc false
    @spec __sandbox__(map, map) :: :ok
    def __sandbox__(%{sandbox: false}, _context), do: :ok

    def __sandbox__(%{repo: repo}, context) do
      sandbox = sandbox!()
      owner = sandbox.start_owner!(repo, shared: not Map.get(context, :async, false))
      Callbacks.on_exit(fn -> sandbox.stop_owner(owner) end)
      :ok
    end

    # The sandbox lives in `ecto_sql`, which is optional, so it is looked up when used.
    defp sandbox! do
      sandbox = Module.concat([Ecto, Adapters, SQL, Sandbox])

      if not Code.ensure_loaded?(sandbox) do
        raise ArgumentError, "Warden.Test.Matrix's sandbox needs ecto_sql; pass `sandbox: false`"
      end

      sandbox
    end

    # Builds every fixture, in order, after the module's own setup blocks.
    # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
    @doc false
    @spec __setup__(module, map, map) :: %{warden_matrix: t}
    def __setup__(module, options, context) do
      matrix = build(module, options, context)
      %{warden_matrix: matrix}
    end

    # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
    @doc false
    @spec build(module, map, map) :: t
    def build(module, options, context) do
      {built, _fixtures} =
        module.__warden_matrix__(:fixtures)
        |> Enum.map_reduce(%{}, fn {kind, name, function, location}, fixtures ->
          fixture_context = Map.put(context, :warden_fixtures, fixtures)
          value = run_fixture!(module, function, fixture_context, {kind, name, location})
          check_fixture!(kind, name, location, value)
          {{kind, name, value}, Map.put(fixtures, name, value)}
        end)

      actors = for {:actor, name, value} <- built, do: {name, value}
      resources = for {:resource, name, value} <- built, do: {name, value}
      fields = Map.take(options, [:authorizer, :repo, :snapshot])
      struct(__MODULE__, Map.merge(fields, %{actors: actors, resources: resources}))
    end

    # A fixture that raises fails with its name and declaration, and the original
    # stacktrace.
    defp run_fixture!(module, function, context, {kind, name, location}) do
      apply(module, function, [context])
    rescue
      error ->
        message = """
        #{kind} fixture #{inspect(name)} (#{location}) raised \
        #{inspect(error.__struct__)}: #{Exception.message(error)}\
        """

        reraise ExUnit.AssertionError, [message: message], __STACKTRACE__
    end

    defp check_fixture!(:resource, _name, _location, %_struct{}), do: :ok
    defp check_fixture!(:actor, _name, _location, %Warden.Actor{}), do: :ok

    defp check_fixture!(:actor, _name, _location, context)
         when is_map(context) and not is_struct(context),
         do: :ok

    defp check_fixture!(kind, name, location, _value) do
      expected = if kind == :actor, do: "an actor or a context map", else: "a struct"

      raise ExUnit.AssertionError,
        message: "#{kind} fixture #{inspect(name)} (#{location}) must return #{expected}"
    end

    @doc """
    Checks the matrix and compares it with its snapshot (`:compare`), prints it
    (`:print`) or rewrites the snapshot (`:update`). The default mode comes from the
    `WARDEN_MATRIX` environment variable (`print` or `update`), which `mix warden.matrix`
    sets. Returns the rendered table.
    """
    @spec run!(t, :compare | :print | :update) :: String.t()
    def run!(%__MODULE__{} = matrix, mode \\ mode()) do
      table = matrix |> model!() |> Snapshot.render()

      case mode do
        :update -> write!(matrix.snapshot, table)
        :print -> IO.puts(table)
        :compare -> compare!(matrix.snapshot, table)
      end

      table
    end

    defp mode do
      case System.get_env(@mode_variable) do
        "update" -> :update
        "print" -> :print
        _unset -> :compare
      end
    end

    # The matrix as data: per policy its actions and resources, the allowed actions per
    # cell, and the redacted fields per cell.
    defp model!(matrix) do
      by_policy = resources_by_policy!(matrix)
      actor_names = Enum.map(matrix.actors, &elem(&1, 0))

      results =
        for {policy, resources} <- by_policy do
          cells =
            Warden.Test.assert_policy_consistent(policy, matrix.actors, resources,
              authorizer: matrix.authorizer,
              repo: matrix.repo
            )

          {policy, resources, cells}
        end

      allowed =
        for {_policy, _resources, cells} <- results,
            {{actor, resource, action}, true} <- cells,
            reduce: %{} do
          acc -> Map.update(acc, {resource, actor}, [action], &[action | &1])
        end

      policies =
        for {policy, resources, _cells} <- results do
          {policy, Dispatch.info!(policy).actions, Enum.map(resources, &elem(&1, 0))}
        end

      %{
        policies: policies,
        actors: actor_names,
        allowed: allowed,
        redacted: redacted(matrix, allowed)
      }
    end

    defp resources_by_policy!(matrix) do
      authorizer = matrix.authorizer

      {placed, unplaced} =
        Enum.split_with(matrix.resources, fn {_name, row} ->
          Policy.policy_for(authorizer, row)
        end)

      by_policy =
        Enum.group_by(placed, fn {_name, row} -> Policy.policy_for(authorizer, row) end)

      missing =
        Enum.reject(authorizer.__warden_catalog__().policies, &Map.has_key?(by_policy, &1))

      errors =
        Enum.map(missing, &"#{inspect(&1)} has no resource fixture") ++
          Enum.map(unplaced, fn {name, %struct{}} ->
            "resource #{inspect(name)} is a #{inspect(struct)}, which has no policy in #{inspect(authorizer)}"
          end)

      if errors != [] do
        raise ExUnit.AssertionError,
          message:
            "the policy matrix is incomplete:\n" <> Enum.map_join(errors, "\n", &("  " <> &1))
      end

      Enum.sort_by(by_policy, fn {policy, _resources} -> inspect(policy) end)
    end

    # The fields `Warden.redact/3` changes, for cells where the actor may take an action
    # and the struct has a field policy.
    defp redacted(matrix, allowed) do
      for {actor_name, actor} <- matrix.actors,
          {resource_name, row} <- matrix.resources,
          Map.has_key?(allowed, {resource_name, actor_name}),
          Fields.fields_for(matrix.authorizer, row) != nil,
          hidden = changed_fields(row, Warden.redact(actor, row, authorizer: matrix.authorizer)),
          hidden != [],
          into: %{},
          do: {{resource_name, actor_name}, hidden}
    end

    defp changed_fields(row, redacted) do
      for {field, value} <- Map.from_struct(row),
          Map.get(redacted, field) != value,
          do: field
    end

    defp write!(path, table) do
      path |> Path.dirname() |> File.mkdir_p!()
      File.write!(path, table)
    end

    defp compare!(path, table) do
      case File.read(path) do
        {:ok, ^table} ->
          :ok

        {:ok, snapshot} ->
          changes = Snapshot.diff(Snapshot.cells(snapshot), Snapshot.cells(table))
          compare_failed!(path, changes)

        {:error, _reason} ->
          message = """
          no policy matrix snapshot at #{path}; write it with `mix warden.matrix --update`\
          """

          raise ExUnit.AssertionError, message: message
      end
    end

    # A snapshot that differs only in layout passes; a changed cell fails.
    defp compare_failed!(_path, []), do: :ok

    defp compare_failed!(path, changes) do
      lines = Enum.map_join(changes, "\n", &("  " <> &1))

      message = """
      the policy matrix differs from #{path} in #{length(changes)} cell(s):
      #{lines}
      Run `mix warden.matrix --update` if the change is intended.\
      """

      raise ExUnit.AssertionError, message: message
    end
  end
end
