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

  @typedoc "What a denial handler returns."
  @type denial_result :: {:error, term} | :null | {:replace, term}

  @doc "Returns the subject (the user) from the Absinthe context. `nil` means anonymous."
  @callback subject(context :: map) :: term

  @doc "Returns the subject's roles. Must return a list of catalog roles."
  @callback roles(subject :: term, context :: map) :: [atom]

  @doc "Returns extra permissions for the subject. Must return a list. Default: `[]`."
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
  Returns a key that identifies what the actor may see. Used to keep subscribers with
  different access from sharing one subscription resolution. The default hashes the
  subject identity (its `:id` when it is a map with one), the roles and the permissions.
  """
  @callback actor_key(Actor.t()) :: String.t()

  @optional_callbacks permissions: 2, check: 2, deny: 1, actor_key: 1

  @option_keys [
    :roles,
    :permissions,
    :role_hierarchy,
    :role_permissions,
    :checks,
    :expose_denial_reasons,
    :spec_compliant_errors
  ]

  defmacro __using__(opts) do
    {opts, _} = Code.eval_quoted(opts, [], __CALLER__)

    catalog =
      case build_catalog(opts) do
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

      @doc false
      def __warden_catalog__, do: unquote(Macro.escape(catalog))
    end
  end

  defmacro __before_compile__(env) do
    catalog = Module.get_attribute(env.module, :__warden_catalog__)
    defines? = &Module.defines?(env.module, &1)

    check_def =
      cond do
        defines?.({:check, 2}) ->
          nil

        catalog.checks != [] ->
          raise CompileError,
            file: env.file,
            line: env.line,
            description:
              "#{inspect(env.module)} declares checks #{inspect(catalog.checks)} " <>
                "but does not define check/2"

        true ->
          quote do
            @doc false
            def check(name, _check) do
              raise Warden.PolicyError,
                    "#{inspect(__MODULE__)} defines no check/2 but a rule used " <>
                      "check(#{inspect(name)})"
            end
          end
      end

    permissions_def =
      unless defines?.({:permissions, 2}) do
        quote do
          @doc false
          def permissions(_subject, _context), do: []
        end
      end

    deny_def =
      unless defines?.({:deny, 1}) do
        quote do
          @doc false
          def deny(denial), do: Warden.Authorizer.default_deny(denial, __warden_catalog__())
        end
      end

    actor_key_def =
      unless defines?.({:actor_key, 1}) do
        quote do
          @doc false
          def actor_key(actor), do: Warden.Authorizer.default_actor_key(actor)
        end
      end

    [check_def, permissions_def, deny_def, actor_key_def]
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  The default denial handler. Returns `"Forbidden"` with `code: "FORBIDDEN"` and,
  only when the authorizer sets `expose_denial_reasons: true`, the missing roles and
  permissions. Items filtered by the `:filter` list policy get `:null` (no error).
  """
  @spec default_deny(Denial.t(), map) :: denial_result
  def default_deny(%Denial{list_policy: :filter, value_index: [_ | _]}, _catalog), do: :null

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

  ## Catalog

  @doc false
  def build_catalog(opts) when is_list(opts) do
    errors = []

    unknown = Keyword.keys(opts) -- @option_keys

    errors =
      if unknown == [],
        do: errors,
        else: ["unknown options: #{inspect(unknown)}" | errors]

    roles = Keyword.get(opts, :roles)

    errors =
      cond do
        roles == nil ->
          ["`:roles` is required" | errors]

        not is_list(roles) or roles == [] ->
          ["`:roles` must be a non-empty list of atoms" | errors]

        Enum.any?(roles, &(not is_atom(&1) or is_nil(&1) or is_boolean(&1))) ->
          ["`:roles` must be a non-empty list of atoms, got: #{inspect(roles)}" | errors]

        length(Enum.uniq(roles)) != length(roles) ->
          ["`:roles` contains duplicates: #{inspect(roles -- Enum.uniq(roles))}" | errors]

        true ->
          errors
      end

    role_set = if is_list(roles), do: MapSet.new(roles), else: MapSet.new()

    perms = Keyword.get(opts, :permissions)

    errors =
      cond do
        perms == nil ->
          errors

        not is_list(perms) ->
          ["`:permissions` must be a list or nil" | errors]

        Enum.any?(perms, &(&1 in [nil, :all])) ->
          ["`:permissions` must not contain nil or :all" | errors]

        true ->
          errors
      end

    perm_set = if is_list(perms), do: MapSet.new(perms), else: nil

    hierarchy = Keyword.get(opts, :role_hierarchy, %{})
    {errors, hierarchy} = validate_hierarchy(hierarchy, role_set, errors)

    role_perms = Keyword.get(opts, :role_permissions, %{})
    errors = validate_role_permissions(role_perms, role_set, perm_set, errors)

    checks = Keyword.get(opts, :checks, [])

    errors =
      if is_list(checks) and Enum.all?(checks, &(is_atom(&1) and not is_nil(&1))),
        do: errors,
        else: ["`:checks` must be a list of atoms" | errors]

    errors =
      Enum.reduce([:expose_denial_reasons, :spec_compliant_errors], errors, fn key, errors ->
        if is_boolean(Keyword.get(opts, key, false)),
          do: errors,
          else: ["`#{inspect(key)}` must be a boolean" | errors]
      end)

    case errors do
      [] ->
        implied =
          Map.new(roles, fn role -> {role, reachable(role, hierarchy)} end)

        {:ok,
         %{
           roles: role_set,
           permissions: perm_set,
           role_hierarchy: hierarchy,
           implied_roles: implied,
           role_permissions: role_perms,
           checks: checks,
           expose_denial_reasons: Keyword.get(opts, :expose_denial_reasons, false),
           spec_compliant_errors: Keyword.get(opts, :spec_compliant_errors, false)
         }}

      errors ->
        {:error, Enum.reverse(errors)}
    end
  end

  def build_catalog(_), do: {:error, ["options must be a keyword list"]}

  defp validate_hierarchy(hierarchy, role_set, errors) when is_map(hierarchy) do
    errors =
      Enum.reduce(hierarchy, errors, fn {role, implied}, errors ->
        errors =
          if MapSet.member?(role_set, role),
            do: errors,
            else: ["`:role_hierarchy` key #{inspect(role)} is not a catalog role" | errors]

        cond do
          not is_list(implied) ->
            ["`:role_hierarchy` value for #{inspect(role)} must be a list of roles" | errors]

          true ->
            Enum.reduce(implied, errors, fn r, errors ->
              if MapSet.member?(role_set, r),
                do: errors,
                else: [
                  "`:role_hierarchy` #{inspect(role)} implies #{inspect(r)}, which is not a catalog role"
                  | errors
                ]
            end)
        end
      end)

    errors =
      if errors == [] do
        case find_cycle(hierarchy) do
          nil -> errors
          cycle -> ["`:role_hierarchy` has a cycle: #{Enum.map_join(cycle, " -> ", &inspect/1)}"]
        end
      else
        errors
      end

    {errors, hierarchy}
  end

  defp validate_hierarchy(_, _role_set, errors),
    do: {["`:role_hierarchy` must be a map" | errors], %{}}

  defp validate_role_permissions(role_perms, role_set, perm_set, errors) when is_map(role_perms) do
    Enum.reduce(role_perms, errors, fn {role, perms}, errors ->
      errors =
        if MapSet.member?(role_set, role),
          do: errors,
          else: ["`:role_permissions` key #{inspect(role)} is not a catalog role" | errors]

      cond do
        perms == :all ->
          errors

        not is_list(perms) ->
          [
            "`:role_permissions` value for #{inspect(role)} must be a list or :all"
            | errors
          ]

        Enum.any?(perms, &(&1 in [nil, :all])) ->
          ["`:role_permissions` for #{inspect(role)} must not contain nil or :all" | errors]

        perm_set == nil ->
          errors

        true ->
          Enum.reduce(perms, errors, fn p, errors ->
            if MapSet.member?(perm_set, p),
              do: errors,
              else: [
                "`:role_permissions` for #{inspect(role)} names #{inspect(p)}, which is not in the permission catalog"
                | errors
              ]
          end)
      end
    end)
  end

  defp validate_role_permissions(_, _, _, errors),
    do: ["`:role_permissions` must be a map" | errors]

  defp reachable(role, hierarchy), do: reachable([role], hierarchy, MapSet.new())

  defp reachable([], _hierarchy, seen), do: seen

  defp reachable([role | rest], hierarchy, seen) do
    if MapSet.member?(seen, role) do
      reachable(rest, hierarchy, seen)
    else
      reachable(Map.get(hierarchy, role, []) ++ rest, hierarchy, MapSet.put(seen, role))
    end
  end

  # Depth-first search for a cycle. Returns the cycle as a list of roles, or nil.
  defp find_cycle(hierarchy) do
    hierarchy
    |> Map.keys()
    |> Enum.sort()
    |> Enum.find_value(fn role -> dfs(role, hierarchy, [role]) end)
  end

  defp dfs(role, hierarchy, stack) do
    hierarchy
    |> Map.get(role, [])
    |> Enum.find_value(fn next ->
      if next in stack do
        Enum.reverse([next | stack])
      else
        dfs(next, hierarchy, [next | stack])
      end
    end)
  end
end
