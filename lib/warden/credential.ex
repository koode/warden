defmodule Warden.Credential do
  @moduledoc """
  How an actor authenticated: a session, an API key, an OAuth token, a system job.

  Returned by `c:Warden.Authorizer.credential/1` and kept in `Warden.Actor.credential`.

    * `method` - any atom. `:session` is a full session (as is a `nil` credential); the
      `session()` rule passes only for it.
    * `scopes` - the scopes the credential grants (strings from the authorizer's
      `credential_scopes:` catalog), or `:all`. A session grants every scope.
    * `tenant` - the tenant the credential is bound to, or `nil`. A bound credential
      denies every tenant-role rule, policy and scope for any other tenant, without
      calling `c:Warden.Authorizer.tenant_roles/3` or the policy.
    * `bounds` - a map that Warden does not read; policies do (for example the teams an API
      key is limited to).
    * `reason` - for system actors, why the actor exists (`Warden.system_actor/2`), else
      `nil`.

  `inspect/1` shows the method, the scopes and whether the credential is bound, never the
  bounds.
  """

  @type t :: %__MODULE__{
          method: atom,
          scopes: [String.t()] | :all,
          tenant: term,
          bounds: map,
          reason: atom
        }

  defstruct method: :session, scopes: :all, tenant: nil, bounds: %{}, reason: nil

  @doc "Returns true for a full session: a `nil` credential or `method: :session`."
  @spec session?(t | nil) :: boolean
  def session?(nil), do: true
  def session?(%__MODULE__{method: :session}), do: true
  def session?(%__MODULE__{}), do: false

  @doc "Returns true when the credential grants `scope`. A session grants every scope."
  @spec grants?(t | nil, String.t()) :: boolean
  def grants?(nil, _scope), do: true
  def grants?(%__MODULE__{method: :session}, _scope), do: true
  def grants?(%__MODULE__{scopes: :all}, _scope), do: true
  def grants?(%__MODULE__{scopes: scopes}, scope) when is_list(scopes), do: scope in scopes
end

defimpl Inspect, for: Warden.Credential do
  import Inspect.Algebra

  def inspect(credential, opts) do
    fields = [
      method: credential.method,
      scopes: credential.scopes,
      bound: credential.tenant != nil
    ]

    concat(["#Warden.Credential<", to_doc(fields, opts), ">"])
  end
end
