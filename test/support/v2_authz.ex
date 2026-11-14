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
    policies: [Warden.Test.V2.Docs, Warden.Test.V2.Brittle],
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
      single_or_many: [batch: true, single: true]
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

  defp single(:mine, %Warden.Check{actor: %Warden.Actor{subject: %{id: id}}, value: value}),
    do: is_map(value) and Map.get(value, :owner_id) == id

  defp single(:mine, %Warden.Check{}), do: false

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

defmodule Warden.Test.V2.Doc do
  @moduledoc false
  defstruct [:id, :workspace_id, :owner_id, public: false, visible: false, body: "doc body"]

  def all do
    [
      %__MODULE__{id: 1, workspace_id: "t1", owner_id: "abby"},
      %__MODULE__{id: 2, workspace_id: "t1", owner_id: "sam"},
      %__MODULE__{id: 3, workspace_id: "t2", owner_id: "abby", public: true},
      %__MODULE__{id: 4, workspace_id: "t2", owner_id: "olivia"},
      %__MODULE__{id: 5, workspace_id: "t1", owner_id: "olivia", public: true}
    ]
  end

  def get(id), do: Enum.find(all(), &(&1.id == id))
end

defmodule Warden.Test.V2.Docs do
  @moduledoc false
  # Read: public docs, or docs the actor owns. Write: docs the actor owns. Webhooks read
  # public docs only. Ids from `arg:` are looked up.
  use Warden.Policy,
    authorizer: Warden.Test.V2.Authz,
    for: Warden.Test.V2.Doc,
    actions: [:read, :write],
    tenant: :workspace_id,
    system_kinds: [:webhook]

  alias Warden.Test.V2.Doc

  @impl true
  def allowed?(action, actor, value, context) do
    notify(context, {:allowed?, action})
    decide(action, actor, value)
  end

  @impl true
  def allowed_many(action, actor, values, context) do
    notify(context, {:allowed_many, action, length(values)})

    case context[:policy_many] do
      nil -> Enum.map(values, &decide(action, actor, &1))
      fun -> fun.(values)
    end
  end

  defp decide(action, actor, {Doc, id}), do: decide(action, actor, Doc.get(id))
  defp decide(_action, _actor, nil), do: false
  defp decide(:read, %Warden.Actor{system?: true}, %Doc{public: public}), do: public
  defp decide(:read, actor, %Doc{} = doc), do: doc.public or owner?(actor, doc)
  defp decide(:write, actor, %Doc{} = doc), do: owner?(actor, doc)

  defp owner?(%Warden.Actor{subject: %{id: id}}, %Doc{owner_id: id}), do: true
  defp owner?(_actor, _doc), do: false

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.Test.V2.Brittle do
  @moduledoc false
  # Returns whatever the test put in the context, to test broken policies.
  use Warden.Policy, authorizer: Warden.Test.V2.Authz, for: Warden.Test.V2.Note, actions: [:read]

  @impl true
  def allowed?(:read, _actor, _value, context) do
    case Map.fetch!(context, :policy_result) do
      fun when is_function(fun, 0) -> fun.()
      result -> result
    end
  end
end
