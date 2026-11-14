defmodule Warden.Authorizer.Callbacks do
  @moduledoc false
  # Calls the optional authorizer callbacks, falling back to Warden's defaults when the
  # authorizer does not define them. (Defaults used to be injected into the authorizer
  # by `use Warden.Authorizer`; dispatching here keeps the user's module free of
  # generated public functions.)

  alias Warden.{Actor, Check, Denial, Policy}
  alias Warden.Policy.Dispatch

  @default_kind :user

  @spec permissions(module, term, map) :: term
  def permissions(authorizer, subject, context) do
    if function_exported?(authorizer, :permissions, 2),
      do: authorizer.permissions(subject, context),
      else: []
  end

  @spec deny(module, Denial.t()) :: term
  def deny(authorizer, %Denial{} = denial) do
    if function_exported?(authorizer, :deny, 1),
      do: authorizer.deny(denial),
      else: Warden.Authorizer.default_deny(denial, authorizer.__warden_catalog__())
  end

  @spec check(module, atom, Check.t()) :: term
  def check(authorizer, name, %Check{} = check) do
    if function_exported?(authorizer, :check, 2) do
      authorizer.check(name, check)
    else
      raise Warden.PolicyError,
            "#{inspect(authorizer)} defines no check/2 but a rule used check(#{inspect(name)})"
    end
  end

  @spec kind(module, term, map) :: term
  def kind(authorizer, subject, context) do
    if function_exported?(authorizer, :kind, 2),
      do: authorizer.kind(subject, context),
      else: @default_kind
  end

  @spec credential(module, map) :: term
  def credential(authorizer, context) do
    if function_exported?(authorizer, :credential, 1),
      do: authorizer.credential(context),
      else: nil
  end

  @spec tenant_roles(module, term, term, map) :: term
  def tenant_roles(authorizer, subject, tenant, context) do
    if function_exported?(authorizer, :tenant_roles, 3) do
      authorizer.tenant_roles(subject, tenant, context)
    else
      raise Warden.PolicyError,
            "#{inspect(authorizer)} defines no tenant_roles/3 but declares tenant roles"
    end
  end

  @spec tenants(module, Actor.t(), map) :: [term]
  def tenants(authorizer, %Actor{} = actor, context) do
    if function_exported?(authorizer, :tenants, 2) do
      case authorizer.tenants(actor, context) do
        tenants when is_list(tenants) ->
          tenants

        other ->
          raise Warden.PolicyError,
                "#{inspect(authorizer)}.tenants/2 must return a list, got: #{inspect(other)}"
      end
    else
      []
    end
  end

  # Where the tenant of a value is: the authorizer's `tenant_of/1`, else the `tenant:`
  # field of the policy registered for the value's struct, else a `:tenant_id` key.
  @spec tenant_of(module, term) :: term
  def tenant_of(authorizer, value) do
    if function_exported?(authorizer, :tenant_of, 1),
      do: authorizer.tenant_of(value),
      else: default_tenant_of(authorizer, value)
  end

  defp default_tenant_of(authorizer, %_struct{} = value) do
    case Policy.policy_for(authorizer, value) do
      nil -> Map.get(value, :tenant_id)
      policy -> policy_tenant(policy, value)
    end
  end

  defp default_tenant_of(_authorizer, value) when is_map(value), do: Map.get(value, :tenant_id)
  defp default_tenant_of(_authorizer, _value), do: nil

  defp policy_tenant(policy, value) do
    case Dispatch.info!(policy).tenant do
      nil -> Map.get(value, :tenant_id)
      field -> Map.get(value, field)
    end
  end

  @spec check_many(module, atom, [Check.t()]) :: term
  def check_many(authorizer, name, checks) do
    if function_exported?(authorizer, :check_many, 2) do
      authorizer.check_many(name, checks)
    else
      raise Warden.PolicyError,
            "#{inspect(authorizer)} defines no check_many/2 but check(#{inspect(name)}) is batched"
    end
  end
end
