defmodule Warden.Rule do
  @moduledoc """
  Rule builders and the rule evaluator.

  A rule is a plain Elixir term, so it can be stored in Absinthe schema `meta`:

  | Builder | Term | Passes when |
  |---|---|---|
  | `public()` | `:public` | always |
  | `authenticated()` | `:authenticated` | the actor has a subject |
  | `role(r)` | `{:role, r}` | the actor has role `r` (after hierarchy expansion) |
  | `any_role(rs)` | `{:any_role, rs}` | the actor has at least one of `rs` |
  | `permission(p)` | `{:permission, p}` | the actor has permission `p` |
  | `all_permissions(ps)` | `{:all_permissions, ps}` | the actor has every permission in `ps` |
  | `any_permission(ps)` | `{:any_permission, ps}` | the actor has at least one of `ps` |
  | `check(name)` / `check(name, opts)` | `{:check, name, opts}` | `c:Warden.Authorizer.check/2` returns `true` |
  | `all_of(rules)` | `{:all, rules}` | every rule passes |
  | `any_of(rules)` | `{:any, rules}` | at least one rule passes |
  | `deny()` | `:deny` | never |
  | `covered()` | `:covered` | always; in Absinthe only on fields of a type with an object rule |
  | `tenant_role(r)` / `tenant_role(r, tenant: src)` | `{:tenant_role, r, opts}` | the actor has tenant role `r` (after `tenant_role_hierarchy`) in the tenant of the value, or of `{:arg, path}` |
  | `kind(k)` / `kind([k, ...])` | `{:kind, [k, ...]}` | the actor's kind is one of them |
  | `credential_scope(s)` | `{:credential_scope, s}` | the credential grants scope `s` (a session grants every scope) |
  | `session()` | `:session` | the credential is a full session |
  | `can(policy, action)` / `can(policy, action, arg: path)` | `{:can, policy, action, opts}` | the `Warden.Policy` allows `action` on the value, or on `{schema, id}` from the argument at `path` |

  There is no negation on purpose: a negated check fails open when actor data is
  incomplete.

  Only a literal `true` from a check grants access. A check may deny with a reason,
  `{:deny, reason}`. Any other value raises `Warden.PolicyError`.

  A system actor (`Warden.system_actor/2`) fails every `authenticated()`, role, tenant
  role, permission, `session()` and `credential_scope/1` rule, and every check whose
  `system_kinds:` does not name its kind. An actor acting on behalf of another
  (`Warden.on_behalf_of/3`) passes a rule only when both actors pass it.
  """

  alias Warden.Authorizer.Catalog
  alias Warden.{Check, Evaluator}

  @type role :: atom
  @type permission :: term
  @type list_policy :: :null_item | :filter | :fail_list

  @type t ::
          :public
          | :authenticated
          | :deny
          | {:role, role}
          | {:any_role, [role, ...]}
          | {:permission, permission}
          | {:all_permissions, [permission, ...]}
          | {:any_permission, [permission, ...]}
          | {:check, atom, keyword}
          | {:all, [t, ...]}
          | {:any, [t, ...]}
          | :covered
          | :session
          | {:tenant_role, atom, keyword}
          | {:kind, [atom, ...]}
          | {:credential_scope, String.t()}
          | {:can, module, atom, keyword}

  @typedoc """
  Result of a failed evaluation. `reason` and `trace` are described in `Warden.Denial`.
  """
  @type failure :: %{
          failed_rule: t,
          missing_roles: [role],
          missing_permissions: [permission],
          reason: term,
          trace: [{t, :ok | {:deny, term}}]
        }

  @doc "Always passes."
  @spec public() :: t
  def public, do: :public

  @doc "Passes when the actor has a subject."
  @spec authenticated() :: t
  def authenticated, do: :authenticated

  @doc "Never passes."
  @spec deny() :: t
  def deny, do: :deny

  @doc "Passes when the actor has `role` (after hierarchy expansion)."
  @spec role(role) :: t
  def role(role), do: {:role, role}

  @doc "Passes when the actor has at least one of `roles`."
  @spec any_role([role, ...]) :: t
  def any_role(roles), do: {:any_role, roles}

  @doc "Passes when the actor has `permission`."
  @spec permission(permission) :: t
  def permission(permission), do: {:permission, permission}

  @doc "Passes when the actor has every permission in `permissions`."
  @spec all_permissions([permission, ...]) :: t
  def all_permissions(permissions), do: {:all_permissions, permissions}

  @doc "Passes when the actor has at least one permission in `permissions`."
  @spec any_permission([permission, ...]) :: t
  def any_permission(permissions), do: {:any_permission, permissions}

  @doc "Passes when `c:Warden.Authorizer.check/2` returns `true` for `name`."
  @spec check(atom, keyword) :: {:check, atom, keyword}
  def check(name, opts \\ []), do: {:check, name, opts}

  @doc """
  Always passes. Marks a field that its object type's rule guards, so a reviewer can tell
  it from a field that is `public()` on purpose. Absinthe accepts it only on fields of an
  object type (or interface) that has an object rule; the core API and `Warden.Plug`
  refuse it.
  """
  @spec covered() :: t
  def covered, do: :covered

  @doc """
  Passes when the actor has tenant role `role` (after `tenant_role_hierarchy`) in a
  tenant. Option `tenant:` says which: `:value` (default) is the tenant of the guarded
  value (`c:Warden.Authorizer.tenant_of/1`), `{:arg, path}` reads it from the field
  arguments. A `nil` tenant denies.
  """
  @spec tenant_role(atom, keyword) :: t
  def tenant_role(role, opts \\ []), do: {:tenant_role, role, opts}

  @doc """
  Passes when the actor's kind (`Warden.Actor.kind/1`) is `kind` or one of `kinds`. For
  a delegated actor both kinds must be listed.
  """
  @spec kind(atom | [atom, ...]) :: t
  def kind(kinds), do: {:kind, List.wrap(kinds)}

  @doc "Passes when the actor's credential grants `scope`. A session grants every scope."
  @spec credential_scope(String.t()) :: t
  def credential_scope(scope), do: {:credential_scope, scope}

  @doc "Passes when the actor's credential is a full session (`nil` or `method: :session`)."
  @spec session() :: t
  def session, do: :session

  @doc """
  Passes when `policy` (a `Warden.Policy` listed in the authorizer's `policies:`) allows
  `action` on the guarded value. With `arg: path`, the policy is asked about
  `{schema, id}` for the id at that argument path (every id of a list), before any
  resolver runs; a missing id denies. Over a list of values the policy is asked once
  (`c:Warden.Policy.allowed_many/4`).
  """
  @spec can(module, atom, keyword) :: t
  def can(policy, action, opts \\ []), do: {:can, policy, action, opts}

  @doc "Passes when every rule passes. Evaluates left to right and stops at the first failure."
  @spec all_of([t, ...]) :: t
  def all_of(rules), do: {:all, rules}

  @doc "Passes when at least one rule passes. Evaluates left to right and stops at the first pass."
  @spec any_of([t, ...]) :: t
  def any_of(rules), do: {:any, rules}

  @doc """
  Validates the shape of a rule. Returns `:ok` or `{:error, [message]}`.
  """
  @spec validate(term) :: :ok | {:error, [String.t()]}
  def validate(rule), do: validate(rule, nil)

  @doc """
  Validates the shape of a rule and, when `catalog` is given, that every role,
  permission and check it names is declared by the authorizer.
  """
  @spec validate(term, nil | map) :: :ok | {:error, [String.t()]}
  def validate(rule, catalog) do
    case do_validate(rule, catalog, []) do
      [] -> :ok
      errors -> {:error, Enum.reverse(errors)}
    end
  end

  defp do_validate(rule, _catalog, errors)
       when rule in [:public, :authenticated, :deny, :covered, :session],
       do: errors

  defp do_validate({:tenant_role, role, opts}, catalog, errors) when is_list(opts) do
    errors = validate_tenant_source(role, opts, errors)
    validate_tenant_role(role, catalog, errors)
  end

  defp do_validate({:kind, [_ | _] = kinds}, catalog, errors) do
    Enum.reduce(kinds, errors, &validate_kind(&1, catalog, &2))
  end

  defp do_validate({:credential_scope, scope}, catalog, errors) when is_binary(scope) do
    scopes = catalog && Map.get(catalog, :credential_scopes)

    if scopes == nil or MapSet.member?(scopes, scope),
      do: errors,
      else: [
        "credential scope #{inspect(scope)} is not in the authorizer's `credential_scopes:`"
        | errors
      ]
  end

  defp do_validate({:role, role}, catalog, errors), do: validate_role(role, catalog, errors)

  defp do_validate({:any_role, [_ | _] = roles}, catalog, errors) do
    Enum.reduce(roles, errors, &validate_role(&1, catalog, &2))
  end

  defp do_validate({:permission, perm}, catalog, errors),
    do: validate_permission(perm, catalog, errors)

  defp do_validate({tag, [_ | _] = perms}, catalog, errors)
       when tag in [:all_permissions, :any_permission] do
    Enum.reduce(perms, errors, &validate_permission(&1, catalog, &2))
  end

  defp do_validate({:check, name, opts}, catalog, errors) when is_atom(name) and is_list(opts) do
    cond do
      not Keyword.keyword?(opts) ->
        ["check(#{inspect(name)}) options must be a keyword list, got: #{inspect(opts)}" | errors]

      catalog != nil and name not in catalog.checks ->
        [
          "check(#{inspect(name)}) is not declared in the authorizer's `checks:` " <>
            "(declared: #{inspect(catalog.checks)})"
          | errors
        ]

      catalog != nil ->
        option_errors = check_option_errors(name, opts, catalog)
        Enum.reverse(option_errors, errors)

      true ->
        errors
    end
  end

  defp do_validate({:can, policy, action, opts}, catalog, errors) when is_list(opts) do
    shape_errors = can_shape_errors(policy, action, opts)

    if shape_errors == [] and catalog != nil,
      do: Enum.reverse(can_catalog_errors(policy, action, catalog), errors),
      else: Enum.reverse(shape_errors, errors)
  end

  defp do_validate({tag, [_ | _] = rules}, catalog, errors) when tag in [:all, :any] do
    Enum.reduce(rules, errors, &do_validate(&1, catalog, &2))
  end

  defp do_validate(other, _catalog, errors) do
    ["invalid rule: #{inspect(other)}" | errors]
  end

  defp check_option_errors(name, opts, catalog) do
    spec = Map.get(catalog[:check_specs] || %{}, name, Catalog.default_check_spec())
    Catalog.check_options_errors(name, opts, spec)
  end

  defp can_shape_errors(policy, action, opts) do
    name = "can(#{inspect(policy)}, #{inspect(action)})"

    cond do
      not plain_atom?(policy) or not plain_atom?(action) ->
        ["#{name} needs a policy module and an action atom"]

      not Keyword.keyword?(opts) or Keyword.keys(opts) -- [:arg] != [] ->
        ["#{name} only takes the option `arg:`"]

      not valid_can_arg?(opts) ->
        ["#{name} `arg:` must be a path of atoms and list indexes, got: #{inspect(opts[:arg])}"]

      true ->
        []
    end
  end

  defp plain_atom?(term), do: is_atom(term) and not is_nil(term)

  defp valid_can_arg?(opts),
    do: not Keyword.has_key?(opts, :arg) or valid_path?(Keyword.fetch!(opts, :arg))

  defp can_catalog_errors(policy, action, catalog) do
    name = "can(#{inspect(policy)}, #{inspect(action)})"
    authorizer = Map.get(catalog, :authorizer)

    with :ok <- listed_policy(policy, catalog, name),
         {:ok, info} <- policy_info(policy, name) do
      cond do
        authorizer != nil and info.authorizer != authorizer ->
          [
            "#{name}: the policy belongs to #{inspect(info.authorizer)}, not #{inspect(authorizer)}"
          ]

        action not in info.actions ->
          [
            "#{name}: the policy has no action #{inspect(action)} (actions: #{inspect(info.actions)})"
          ]

        true ->
          []
      end
    end
  end

  defp listed_policy(policy, catalog, name) do
    if policy in Map.get(catalog, :policies, []),
      do: :ok,
      else: ["#{name}: #{inspect(policy)} is not in the authorizer's `policies:`"]
  end

  defp policy_info(policy, name) do
    if match?({:module, _module}, Code.ensure_compiled(policy)) and
         function_exported?(policy, :__warden_policy__, 1) do
      {:ok, policy.__warden_policy__(:info)}
    else
      ["#{name}: #{inspect(policy)} is not a Warden policy (use Warden.Policy)"]
    end
  end

  defp validate_tenant_source(role, opts, errors) do
    cond do
      not Keyword.keyword?(opts) or Keyword.keys(opts) -- [:tenant] != [] ->
        ["tenant_role(#{inspect(role)}) only takes the option `tenant:`" | errors]

      valid_tenant_source?(Keyword.get(opts, :tenant, :value)) ->
        errors

      true ->
        message = """
        tenant_role(#{inspect(role)}) `tenant:` must be :value or {:arg, path}, got: \
        #{inspect(opts[:tenant])}\
        """

        [message | errors]
    end
  end

  defp valid_tenant_source?(:value), do: true
  defp valid_tenant_source?({:arg, path}), do: valid_path?(path)
  defp valid_tenant_source?(_source), do: false

  @doc """
  Returns true when `rule` has a leaf that reads the field arguments:
  `tenant_role(r, tenant: {:arg, path})` or `can(policy, action, arg: path)`. Such
  leaves belong in field and argument rules, never in object rules.
  """
  @spec reads_arguments?(term) :: boolean
  def reads_arguments?({tag, rules}) when tag in [:all, :any] and is_list(rules),
    do: Enum.any?(rules, &reads_arguments?/1)

  def reads_arguments?({:tenant_role, _role, opts}) when is_list(opts),
    do: match?({:arg, _path}, Keyword.get(opts, :tenant))

  def reads_arguments?({:can, _policy, _action, opts}) when is_list(opts),
    do: Keyword.has_key?(opts, :arg)

  def reads_arguments?(_rule), do: false

  @doc false
  # An argument path: a non-empty list of atoms and list indexes.
  @spec valid_path?(term) :: boolean
  def valid_path?([_ | _] = path),
    do: Enum.all?(path, &((is_atom(&1) and not is_nil(&1)) or (is_integer(&1) and &1 >= 0)))

  def valid_path?(_path), do: false

  defp validate_tenant_role(role, _catalog, errors) when not is_atom(role) or is_nil(role),
    do: ["tenant roles must be atoms, got: #{inspect(role)}" | errors]

  defp validate_tenant_role(_role, nil, errors), do: errors

  defp validate_tenant_role(role, catalog, errors) do
    case Map.get(catalog, :tenant_roles) do
      nil ->
        ["tenant_role(#{inspect(role)}) needs `tenant_roles:` in the authorizer" | errors]

      tenant_roles ->
        if MapSet.member?(tenant_roles, role),
          do: errors,
          else: [unknown_tenant_role(role, tenant_roles) | errors]
    end
  end

  defp unknown_tenant_role(role, tenant_roles) do
    """
    tenant role #{inspect(role)} is not in the authorizer's tenant role catalog \
    (declared: #{inspect(Enum.sort(tenant_roles))})\
    """
  end

  defp validate_kind(kind, _catalog, errors) when not is_atom(kind) or is_nil(kind),
    do: ["kinds must be atoms, got: #{inspect(kind)}" | errors]

  defp validate_kind(:anonymous, _catalog, errors), do: errors
  defp validate_kind(_kind, nil, errors), do: errors

  defp validate_kind(kind, catalog, errors) do
    kinds = Map.get(catalog, :kinds, MapSet.new([:user]))

    if MapSet.member?(kinds, kind),
      do: errors,
      else: [
        "kind #{inspect(kind)} is not in the authorizer's `kinds:` (declared: #{inspect(Enum.sort(kinds))})"
        | errors
      ]
  end

  defp validate_role(role, nil, errors) when is_atom(role) and not is_nil(role), do: errors

  defp validate_role(role, catalog, errors) when is_atom(role) and not is_nil(role) do
    if MapSet.member?(catalog.roles, role) do
      errors
    else
      [
        "role #{inspect(role)} is not in the authorizer's role catalog " <>
          "(declared: #{inspect(Enum.sort(catalog.roles))})"
        | errors
      ]
    end
  end

  defp validate_role(role, _catalog, errors),
    do: ["roles must be atoms, got: #{inspect(role)}" | errors]

  defp validate_permission(perm, _catalog, errors) when perm in [nil, :all] do
    ["#{inspect(perm)} is not a valid permission name" | errors]
  end

  defp validate_permission(_perm, nil, errors), do: errors
  defp validate_permission(_perm, %{permissions: nil}, errors), do: errors

  defp validate_permission(perm, catalog, errors) do
    if MapSet.member?(catalog.permissions, perm) do
      errors
    else
      ["permission #{inspect(perm)} is not in the authorizer's permission catalog" | errors]
    end
  end

  @doc """
  Evaluates `rule` for the check context `check` (a `%Warden.Check{}` with at least
  `actor` set). `authorizer` handles `check(...)` rules.

  Returns `:ok` or `{:deny, failure}`.
  """
  @spec evaluate(t, Check.t(), module) :: :ok | {:deny, failure}
  def evaluate(rule, %Check{} = check, authorizer) do
    {result, _actor, _tenant} = Evaluator.one(rule, check, authorizer)
    result
  end
end
