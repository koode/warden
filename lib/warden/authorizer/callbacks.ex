defmodule Warden.Authorizer.Callbacks do
  @moduledoc false
  # Calls the optional authorizer callbacks, falling back to Warden's defaults when the
  # authorizer does not define them. (Defaults used to be injected into the authorizer
  # by `use Warden.Authorizer`; dispatching here keeps the user's module free of
  # generated public functions.)

  alias Warden.{Check, Denial}

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
end
