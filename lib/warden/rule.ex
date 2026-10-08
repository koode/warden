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

  There is no negation on purpose: a negated check fails open when actor data is
  incomplete.

  Only a literal `true` from a check grants access. Any value other than `true` or
  `false` raises `Warden.PolicyError`.
  """

  alias Warden.{Actor, Check}

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

  @typedoc "Result of a failed evaluation."
  @type failure :: %{
          failed_rule: t,
          missing_roles: [role],
          missing_permissions: [permission]
        }

  @list_policies [:null_item, :filter, :fail_list]

  @doc false
  def list_policies, do: @list_policies

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
  @spec check(atom, keyword) :: t
  def check(name, opts \\ []), do: {:check, name, opts}

  @doc "Passes when every rule passes. Evaluates left to right and stops at the first failure."
  @spec all_of([t, ...]) :: t
  def all_of(rules), do: {:all, rules}

  @doc "Passes when at least one rule passes. Evaluates left to right and stops at the first pass."
  @spec any_of([t, ...]) :: t
  def any_of(rules), do: {:any, rules}

  ## Validation

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

  defp do_validate(rule, _catalog, errors) when rule in [:public, :authenticated, :deny],
    do: errors

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

      true ->
        errors
    end
  end

  defp do_validate({tag, [_ | _] = rules}, catalog, errors) when tag in [:all, :any] do
    Enum.reduce(rules, errors, &do_validate(&1, catalog, &2))
  end

  defp do_validate(other, _catalog, errors) do
    ["invalid rule: #{inspect(other)}" | errors]
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

  @doc false
  # True when the rule is exactly `:public`, so no runtime check is needed.
  def trivially_public?(:public), do: true
  def trivially_public?(_), do: false

  @doc false
  # Combines rules with AND, dropping `:public` and `nil`.
  def conjoin(rules) do
    case rules |> Enum.reject(&(&1 in [nil, :public])) |> Enum.uniq() do
      [] -> nil
      [rule] -> rule
      rules -> {:all, rules}
    end
  end

  ## Evaluation

  @doc """
  Evaluates `rule` for the check context `check` (a `%Warden.Check{}` with at least
  `actor` set). `authorizer` handles `check(...)` rules.

  Returns `:ok` or `{:deny, failure}`.
  """
  @spec evaluate(t, Check.t(), module) :: :ok | {:deny, failure}
  def evaluate(rule, %Check{} = check, authorizer) do
    case eval(rule, check, authorizer) do
      :ok -> :ok
      {:deny, failed, roles, perms} -> {:deny, failure(failed, roles, perms)}
    end
  end

  defp failure(failed, roles, perms) do
    %{
      failed_rule: failed,
      missing_roles: Enum.uniq(roles),
      missing_permissions: Enum.uniq(perms)
    }
  end

  defp eval(:public, _check, _authz), do: :ok
  defp eval(:deny, _check, _authz), do: {:deny, :deny, [], []}

  defp eval(:authenticated, %Check{actor: actor}, _authz) do
    if Actor.anonymous?(actor), do: {:deny, :authenticated, [], []}, else: :ok
  end

  defp eval({:role, role} = rule, %Check{actor: actor}, _authz) do
    if MapSet.member?(actor.roles, role), do: :ok, else: {:deny, rule, [role], []}
  end

  defp eval({:any_role, roles} = rule, %Check{actor: actor}, _authz) do
    if Enum.any?(roles, &MapSet.member?(actor.roles, &1)),
      do: :ok,
      else: {:deny, rule, roles, []}
  end

  defp eval({:permission, perm} = rule, %Check{actor: actor}, _authz) do
    if has_permission?(actor, perm), do: :ok, else: {:deny, rule, [], [perm]}
  end

  defp eval({:all_permissions, perms} = rule, %Check{actor: actor}, _authz) do
    case Enum.reject(perms, &has_permission?(actor, &1)) do
      [] -> :ok
      missing -> {:deny, rule, [], missing}
    end
  end

  defp eval({:any_permission, perms} = rule, %Check{actor: actor}, _authz) do
    if Enum.any?(perms, &has_permission?(actor, &1)),
      do: :ok,
      else: {:deny, rule, [], perms}
  end

  defp eval({:check, name, opts} = rule, %Check{} = check, authz) do
    case authz.check(name, %{check | name: name, opts: opts}) do
      true ->
        :ok

      false ->
        {:deny, rule, [], []}

      other ->
        raise Warden.PolicyError,
              "#{inspect(authz)}.check(#{inspect(name)}, ...) must return true or false, " <>
                "got: #{inspect(other)}"
    end
  end

  defp eval({:all, rules}, check, authz) do
    Enum.reduce_while(rules, :ok, fn rule, :ok ->
      case eval(rule, check, authz) do
        :ok -> {:cont, :ok}
        denial -> {:halt, denial}
      end
    end)
  end

  defp eval({:any, rules} = rule, check, authz) do
    Enum.reduce_while(rules, {:deny, rule, [], []}, fn sub, {:deny, _, roles, perms} ->
      case eval(sub, check, authz) do
        :ok -> {:halt, :ok}
        {:deny, _, r, p} -> {:cont, {:deny, rule, roles ++ r, perms ++ p}}
      end
    end)
  end

  defp eval(other, _check, _authz) do
    raise Warden.PolicyError, "invalid rule: #{inspect(other)}"
  end

  defp has_permission?(%Actor{permissions: perms}, perm) do
    MapSet.member?(perms, :all) or MapSet.member?(perms, perm)
  end
end
