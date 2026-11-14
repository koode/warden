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
      :reasoned,
      :mine,
      typed: [opts: [role: {:in, [:owner, :admin]}], required: [:role]],
      hooked: [system_kinds: [:webhook]],
      slow: [timeout: 200],
      visible: [batch: true],
      slow_many: [batch: true, timeout: 200],
      configured_many: [batch: true],
      single_or_many: [batch: true]
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

  @single_checks [:plain, :reasoned, :mine, :typed, :hooked, :slow, :single_or_many]

  @impl true
  def check(name, %Warden.Check{context: context} = check) when name in @single_checks do
    notify(context, {:check, name})
    single(name, check)
  end

  defp single(:plain, %Warden.Check{context: context}), do: Map.get(context, :plain, false)

  defp single(:reasoned, %Warden.Check{context: context}),
    do: Map.get(context, :reasoned, {:deny, :not_member})

  defp single(:mine, %Warden.Check{actor: actor, value: value}),
    do: is_map(value) and Map.get(value, :owner_id) == actor.subject.id

  defp single(:typed, %Warden.Check{}), do: true
  defp single(:hooked, %Warden.Check{}), do: true

  defp single(:slow, %Warden.Check{context: context}) do
    Process.sleep(Map.get(context, :sleep, 0))
    Map.get(context, :slow_result, true)
  end

  defp single(:single_or_many, %Warden.Check{}), do: true

  # check_many/2 answers every batched check. A check/2 clause exists only for
  # :single_or_many, so single values of the others go through check_many/2 too.
  @impl true
  def check_many(name, checks) do
    context = List.first(checks).context
    notify(context, {:check_many, name, length(checks)})
    many(name, checks, context)
  end

  defp many(:visible, checks, _context),
    do: Enum.map(checks, &(is_map(&1.value) and Map.get(&1.value, :visible, false)))

  defp many(:slow_many, checks, context) do
    Process.sleep(Map.get(context, :sleep, 0))
    Enum.map(checks, fn _check -> true end)
  end

  defp many(:configured_many, checks, context), do: Map.fetch!(context, :many_result).(checks)
  defp many(:single_or_many, checks, _context), do: Enum.map(checks, fn _check -> false end)

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

defmodule Warden.Test.Decisions do
  @moduledoc false
  # Forwards `[:warden, :decision]` events to the test process that attached, when they
  # were emitted by that process (or a process it started), so async tests do not see
  # each other's events.

  def attach do
    handler = "warden-test-#{System.unique_integer([:positive])}"
    :ok = :telemetry.attach(handler, [:warden, :decision], &__MODULE__.handle/4, self())
    ExUnit.Callbacks.on_exit(fn -> :telemetry.detach(handler) end)
    handler
  end

  def handle(_event, measurements, metadata, test_pid) do
    if self() == test_pid or test_pid in Process.get(:"$callers", []) do
      send(test_pid, {:decision, measurements, metadata})
    end
  end
end
