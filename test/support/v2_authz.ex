defmodule Warden.Test.V2.Authz do
  @moduledoc false
  # The authorizer of the v0.2 test suite: kinds, tenant roles, credential scopes, a
  # policy and checks with options, reasons, batching and timeouts. Tests steer the
  # callbacks through the context and count calls with messages to `context.test_pid`.
  use Warden.Authorizer,
    roles: [:instance_admin, :staff],
    permissions: ["docs:export"],
    role_permissions: %{instance_admin: :all},
    kinds: [:user, :agent, :system, :webhook],
    tenant_roles: [:owner, :admin, :member, :guest],
    tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
    credential_scopes: ["docs:read", "docs:write"],
    checks: [
      :plain,
      typed: [opts: [role: {:in, [:owner, :admin]}], required: [:role]]
    ]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def kind(user, _context), do: Map.get(user, :kind, :user)

  @impl true
  def credential(context), do: context[:credential]

  @impl true
  def tenant_roles(user, tenant, context) do
    notify(context, {:tenant_roles, user.id, tenant})

    case context[:tenant_roles_fun] do
      nil -> user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
      fun -> fun.(user, tenant)
    end
  end

  @impl true
  def tenants(actor, _context), do: actor.subject |> Map.get(:memberships, %{}) |> Map.keys()

  @impl true
  def check(:plain, %Warden.Check{context: context}), do: Map.get(context, :plain, false)
  def check(:typed, %Warden.Check{}), do: true

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.Test.V2.People do
  @moduledoc false
  # Abby owns tenant "t1" and is a guest in "t2"; Sam is a member of "t1"; Olivia is an
  # agent with a guest membership in "t1".

  def abby, do: %{id: "abby", memberships: %{"t1" => [:owner], "t2" => [:guest]}}
  def sam, do: %{id: "sam", memberships: %{"t1" => [:member]}}
  def olivia, do: %{id: "olivia", kind: :agent, memberships: %{"t1" => [:guest]}}
  def admin, do: %{id: "root", roles: [:instance_admin]}

  def context(user, extra \\ %{}), do: Map.merge(%{current_user: user, test_pid: self()}, extra)

  def actor(user, extra \\ %{}),
    do: Warden.actor(context(user, extra), authorizer: Warden.Test.V2.Authz)
end
