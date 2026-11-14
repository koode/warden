defmodule Warden.RedteamMythos.RegistryAuthz do
  @moduledoc false
  use Warden.Authorizer,
    roles: [:staff],
    policies: [Warden.RedteamMythos.ArchiveRecords, Warden.RedteamMythos.Records],
    checks: [:workspace_member]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def credential(context), do: context[:credential]

  @impl true
  def check(:workspace_member, %Warden.Check{actor: actor, value: workspace_id}),
    do: workspace_id in Map.get(actor.subject, :workspaces, [])
end

defmodule Warden.RedteamMythos.Record do
  @moduledoc false
  defstruct [:id, :workspace_id, :archive_id]
end

defmodule Warden.RedteamMythos.ArchiveRecords do
  @moduledoc false
  use Warden.Policy,
    authorizer: Warden.RedteamMythos.RegistryAuthz,
    for: Warden.RedteamMythos.Record,
    actions: [:read],
    tenant: :archive_id

  @impl true
  def allowed?(:read, _actor, _record, _context), do: true
end

defmodule Warden.RedteamMythos.Records do
  @moduledoc false
  use Warden.Policy,
    authorizer: Warden.RedteamMythos.RegistryAuthz,
    for: Warden.RedteamMythos.Record,
    actions: [:read],
    tenant: :workspace_id

  @impl true
  def allowed?(:read, _actor, _record, _context), do: false
end

defmodule Warden.RedteamMythos.RegistryTest do
  # Red-team of the policy registry and of bound credentials on values without a tenant.
  # Every test asserts the secure behaviour, so a failing test is an open hole.
  use ExUnit.Case, async: true

  import Warden.Rule

  alias Phoenix.Socket
  alias Warden.Credential
  alias Warden.Phoenix.Channel
  alias Warden.RedteamMythos.{Record, RegistryAuthz}

  defp bound_context do
    key = %Credential{method: :api_key, scopes: :all, tenant: "t1"}
    user = %{id: "abby", roles: [:staff], workspaces: ["t1", "t2"]}
    %{current_user: user, credential: key}
  end

  defp registry_outcome(fun) do
    {:ok, fun.()}
  rescue
    _error in [Warden.PolicyError, ArgumentError] -> :refused
  end

  describe "HOLE: two policies for one struct, the first in the list wins silently" do
    test "looking up the policy of a struct with two policies is refused" do
      record = %Record{id: 1, workspace_id: "t2"}

      assert registry_outcome(fn -> Warden.Policy.policy_for(RegistryAuthz, record) end) ==
               :refused
    end

    test "goal 11: the binding screen does not depend on the order of `policies:`" do
      foreign = %Record{id: 1, workspace_id: "t2"}

      outcome =
        registry_outcome(fn ->
          Warden.allowed?(bound_context(), role(:staff),
            value: foreign,
            authorizer: RegistryAuthz
          )
        end)

      assert outcome in [:refused, {:ok, false}], """
      a credential bound to t1 read a record of t2: the tenant of the record was looked up \
      with the `tenant:` field of the first policy listed for its struct, not the second\
      """
    end
  end

  describe "HOLE goal 11: a bound credential joins another tenant's channel" do
    test "the documented join check with the topic id as value is not bound" do
      socket = %Socket{assigns: bound_context(), topic: "workspace:t2"}

      joined =
        Channel.authorize_join(socket, check(:workspace_member),
          value: "t2",
          authorizer: RegistryAuthz
        )

      assert {:error, _reply} = joined, """
      an API key bound to workspace t1 joined workspace:t2: the value is the bare id from \
      the topic, its tenant is unknown, so the binding screen lets the check decide as for \
      a full session\
      """
    end
  end

  describe "held: a bound credential and values with a known tenant" do
    test "a map or struct that carries the tenant is screened before the check" do
      socket = %Socket{assigns: bound_context(), topic: "workspace:t2"}

      assert {:error, %{reason: "forbidden"}} =
               Channel.authorize_join(socket, authenticated(),
                 value: %{tenant_id: "t2"},
                 authorizer: RegistryAuthz
               )

      assert {:ok, _socket} =
               Channel.authorize_join(socket, authenticated(),
                 value: %{tenant_id: "t1"},
                 authorizer: RegistryAuthz
               )
    end
  end
end
