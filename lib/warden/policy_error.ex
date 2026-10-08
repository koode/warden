defmodule Warden.PolicyError do
  @moduledoc """
  Raised when an authorization policy is broken: a check returned something other than
  a boolean, an authorizer callback broke its contract, or a denial handler returned an
  unsupported value.

  A `Warden.PolicyError` is a bug in the application's policy code. Warden fails closed:
  it never treats such a value as a grant.
  """
  defexception [:message]
end
