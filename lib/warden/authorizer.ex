defmodule Warden.Authorizer do
  @moduledoc """
  The behaviour for the application's authorizer module.

      defmodule MyApp.Authz do
        use Warden.Authorizer,
          roles: [:admin, :editor, :viewer],
          permissions: ["posts:read", "posts:write"],
          role_hierarchy: %{admin: [:editor], editor: [:viewer]},
          role_permissions: %{admin: :all, editor: ["posts:write"], viewer: ["posts:read"]},
          checks: [:self]

        @impl true
        def subject(context), do: context[:current_user]

        @impl true
        def roles(user, _context), do: user.roles

        @impl true
        def check(:self, %Warden.Check{actor: actor, value: value}),
          do: value.id == actor.subject.id
      end

  ## Options

    * `:roles` (required) - the role catalog, a list of atoms.
    * `:permissions` - the permission catalog. `nil` (default) accepts any term.
    * `:role_hierarchy` - `%{role => [implied_role]}`. Must be acyclic and use catalog
      roles only.
    * `:role_permissions` - `%{role => [permission] | :all}`. `:all` grants every
      permission.
    * `:checks` - the names handled by `c:check/2`. A rule that names an undeclared check
      fails compilation. If any check is declared, `c:check/2` must be defined.
    * `:expose_denial_reasons` - when `true`, the default `c:deny/1` adds
      `missing_roles` and `missing_permissions` to the error extensions. Default `false`.
    * `:spec_compliant_errors` - set to `true` when you run Absinthe with
      `spec_compliant_errors: true`, so the default error puts `code` in `extensions`
      only once. Default `false`.

  Every option is validated at compile time.
  """

  alias Warden.{Actor, Check, Denial}
  alias Warden.Authorizer.Catalog

  @typedoc "What a denial handler returns."
  @type denial_result :: {:error, term} | :null | {:replace, term}

  @doc """
  Returns the subject (the user) from the context. `nil` or `false` means anonymous;
  `:error` or `{:error, _}` raises `Warden.PolicyError`.

  The context is the Absinthe context (GraphQL), the conn context (`Warden.Plug`, see
  `c:conn_context/1`) or the map given to the core API.

  How often `subject/1`, `roles/2` and `permissions/2` run:

    * GraphQL: once per document execution (and once per subscription publish);
    * `Warden.Plug`: once per check (`call/2`, `authorize/3`, `authorize!/3`);
    * the core API: once per call given a context map; never for a call given an actor.

  Keep them cheap: read from the context (assigns), and load the user and its roles in
  an earlier plug or in the code that builds the context, not in these callbacks.
  """
  @callback subject(context :: map) :: term

  @doc """
  Returns the subject's roles. Must return a list of catalog roles. Runs as often as
  `c:subject/1`; read from the subject or the context, do not load data here.
  """
  @callback roles(subject :: term, context :: map) :: [atom]

  @doc """
  Returns extra permissions for the subject. Must return a list. Default: `[]`. Runs as
  often as `c:subject/1`; read from the subject or the context, do not load data here.
  """
  @callback permissions(subject :: term, context :: map) :: [term]

  @doc "Handles a `check(name, opts)` rule. Must return `true` or `false`."
  @callback check(name :: atom, check :: Check.t()) :: boolean

  @doc """
  Turns a denial into a result: `{:error, term}`, `:null` or `{:replace, value}`.

  The default returns `{:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}`,
  and `:null` for list items under the `:filter` policy.
  """
  @callback deny(Denial.t()) :: denial_result

  @doc """
  Opts in to subscription sharing. Absinthe resolves an event once per `context_id` and
  document and sends the result to every subscriber with that id. By default Warden
  removes any `context_id` your `config` sets, so every subscription resolves on its
  own. When you define `actor_key/2`, Warden instead appends the key you return to the
  `context_id`: subscriptions whose keys are equal share one resolution, and share its
  fate (a revocation that should hit one of them hits the shared resolution only when
  the key changes). Return `nil` to not share this subscription.

  The key must cover everything your rules read: subject attributes, roles,
  permissions, and any context values a `check` uses. `default_actor_key/1` hashes the
  subject identity, roles and permissions, and can be a building block.
  """
  @callback actor_key(Actor.t(), context :: map) :: String.t() | nil

  @doc """
  `Warden.Plug` only. Returns the context to build the actor from for a conn. Default:
  `Map.put(conn.assigns, :conn, conn)`, so a `subject/1` that reads
  `context[:current_user]` serves GraphQL and REST alike. Runs on every Plug check (there
  is no actor cache); keep it cheap.
  """
  @callback conn_context(conn :: struct()) :: map

  @doc """
  `Warden.Plug` only. Handles a denied request: send a response. Whatever it returns,
  the plug halts the conn, and sends the default response when the handler sent none.
  """
  @callback deny_conn(conn :: struct(), Denial.t()) :: struct()

  @optional_callbacks permissions: 2,
                      check: 2,
                      deny: 1,
                      actor_key: 2,
                      conn_context: 1,
                      deny_conn: 2

  defmacro __using__(opts) do
    {opts, _} = Code.eval_quoted(opts, [], __CALLER__)

    catalog =
      case Catalog.build(opts) do
        {:ok, catalog} ->
          catalog

        {:error, errors} ->
          raise CompileError,
            file: __CALLER__.file,
            line: __CALLER__.line,
            description:
              "invalid Warden.Authorizer options in #{inspect(__CALLER__.module)}:\n" <>
                Enum.map_join(errors, "\n", &("  * " <> &1))
      end

    quote do
      @behaviour Warden.Authorizer
      @before_compile Warden.Authorizer
      @__warden_catalog__ unquote(Macro.escape(catalog))

      def __warden_catalog__, do: unquote(Macro.escape(catalog))
    end
  end

  # Optional callbacks are not injected: `Warden.Authorizer.Callbacks` falls back to the
  # defaults when the authorizer does not define them. Only compile-time checks run here.
  defmacro __before_compile__(env) do
    catalog = Module.get_attribute(env.module, :__warden_catalog__)
    defines? = &Module.defines?(env.module, &1)

    if catalog.checks != [] and not defines?.({:check, 2}) do
      raise CompileError,
        file: env.file,
        line: env.line,
        description:
          "#{inspect(env.module)} declares checks #{inspect(catalog.checks)} " <>
            "but does not define check/2"
    end

    if defines?.({:actor_key, 1}) and not defines?.({:actor_key, 2}) do
      raise CompileError,
        file: env.file,
        line: env.line,
        description:
          "#{inspect(env.module)} defines actor_key/1; the callback is actor_key(actor, context)"
    end

    quote do
      def __warden_dedup__, do: unquote(defines?.({:actor_key, 2}))
    end
  end

  @doc """
  The default denial handler. Returns `"Forbidden"` with `code: "FORBIDDEN"` and,
  only when the authorizer sets `expose_denial_reasons: true`, the missing roles and
  permissions. Items filtered by the `:filter` list policy get `:null` (no error).
  """
  @spec default_deny(Denial.t(), map) :: {:error, map} | :null
  def default_deny(%Denial{list_policy: :filter, value_index: [_ | _]}, _catalog), do: :null

  # A denied object reads as "not found": no error, so a client cannot tell an object it
  # may not see from one that does not exist.
  def default_deny(%Denial{kind: :object}, _catalog), do: :null

  def default_deny(%Denial{} = denial, catalog) do
    ext = %{code: "FORBIDDEN"}

    ext =
      if catalog[:expose_denial_reasons] do
        Map.merge(ext, %{
          missing_roles: Enum.map(denial.missing_roles, &to_string/1),
          missing_permissions: Enum.map(denial.missing_permissions, &to_string/1)
        })
      else
        ext
      end

    if catalog[:spec_compliant_errors] do
      {:error, Map.put(ext, :message, "Forbidden")}
    else
      {:error, %{message: "Forbidden", extensions: ext}}
    end
  end

  @doc "The default actor key: a SHA-256 over subject identity, roles and permissions."
  @spec default_actor_key(Actor.t()) :: String.t()
  def default_actor_key(%Actor{} = actor) do
    identity =
      case actor.subject do
        %{id: id} -> {:id, id}
        other -> {:subject, other}
      end

    {identity, Enum.sort(actor.roles), Enum.sort(actor.permissions)}
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.url_encode64(padding: false)
  end
end
