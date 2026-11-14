defmodule Warden.Test.V2.Authz do
  @moduledoc false
  # The authorizer of the v0.2 test suite: kinds, tenant roles, credential scopes, a
  # policy and checks with options, reasons, batching and timeouts. Tests steer the checks
  # through the context.
  use Warden.Authorizer,
    roles: [:instance_admin, :staff],
    permissions: ["docs:export"],
    role_permissions: %{instance_admin: :all},
    checks: [
      :plain,
      typed: [opts: [role: {:in, [:owner, :admin]}], required: [:role]]
    ]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def check(:plain, %Warden.Check{context: context}), do: Map.get(context, :plain, false)
  def check(:typed, %Warden.Check{}), do: true
end
