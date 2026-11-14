defmodule Warden.RedteamMythos.CoreAuthz do
  @moduledoc false
  use Warden.Authorizer,
    roles: [:staff],
    kinds: [:user, :agent, :webhook],
    tenant_roles: [:member],
    fields: [Warden.RedteamMythos.DocFields],
    checks: [
      :open,
      stuck: [timeout: 100],
      stuck_batch: [batch: true, timeout: 100]
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
  def tenant_roles(user, tenant, _context),
    do: user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])

  @impl true
  def check(:open, %Warden.Check{value: value}),
    do: is_map(value) and Map.get(value, :open, false)

  def check(:stuck, %Warden.Check{context: context}) do
    send(context.test_pid, :stuck_called)
    Process.sleep(:infinity)
  end

  @impl true
  def check_many(:stuck_batch, checks) do
    send(List.first(checks).context.test_pid, {:stuck_batch_called, length(checks)})
    Process.sleep(:infinity)
  end
end

defmodule Warden.RedteamMythos.Doc do
  @moduledoc false
  defstruct [:id, :tenant_id, open: false, body: "doc body", children: []]
end

defmodule Warden.RedteamMythos.DocFields do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.RedteamMythos.CoreAuthz, for: Warden.RedteamMythos.Doc

  redact :body, with: "[hidden]", unless: any_of([role(:staff), check(:stuck)])
end

defmodule Warden.RedteamMythos.CoreTest do
  # Red-team of the core API. Every test asserts the secure behaviour, so a failing test
  # is an open hole.
  use ExUnit.Case, async: true

  import Warden.Rule

  alias Warden.Credential
  alias Warden.RedteamMythos.{CoreAuthz, Doc}

  @timeout 100
  @values 12

  defp context(user, extra \\ %{}),
    do: Map.merge(%{current_user: user, test_pid: self()}, extra)

  defp abby, do: %{id: "abby", memberships: %{"t1" => [:member]}}

  defp elapsed_ms(fun) do
    started = System.monotonic_time(:millisecond)
    result = fun.()
    {result, System.monotonic_time(:millisecond) - started}
  end

  defp stuck_calls(count) do
    receive do
      :stuck_called -> stuck_calls(count + 1)
    after
      0 -> count
    end
  end

  describe "HOLE: a check that times out is waited for once per value" do
    test "filter/4 over #{@values} values waits about one timeout, not one per value" do
      values = Enum.map(1..@values, &%{id: &1})

      {kept, elapsed} =
        elapsed_ms(fn ->
          Warden.filter(context(abby()), check(:stuck), values, authorizer: CoreAuthz)
        end)

      assert kept == []

      assert elapsed < 4 * @timeout, """
      #{@values} values took #{elapsed} ms with a #{@timeout} ms timeout: the request waits \
      the full timeout again for every value after the check was already unavailable\
      """
    end

    test "after a timeout the unavailable check is not called again for the same call" do
      values = Enum.map(1..@values, &%{id: &1})
      Warden.filter(context(abby()), check(:stuck), values, authorizer: CoreAuthz)

      assert stuck_calls(0) <= 2
    end

    test "redact/3 over a list waits about one timeout for a timed-out rule" do
      docs = Enum.map(1..@values, &%Doc{id: &1})

      {redacted, elapsed} =
        elapsed_ms(fn -> Warden.redact(context(abby()), docs, authorizer: CoreAuthz) end)

      assert Enum.all?(redacted, &(&1.body == "[hidden]"))
      assert elapsed < 4 * @timeout
    end
  end

  describe "held: a batched check that times out" do
    test "is waited for once for the whole list and denies every value" do
      values = Enum.map(1..@values, &%{id: &1})

      {kept, elapsed} =
        elapsed_ms(fn ->
          Warden.filter(context(abby()), check(:stuck_batch), values, authorizer: CoreAuthz)
        end)

      assert kept == []
      assert elapsed < 4 * @timeout
      assert_received {:stuck_batch_called, @values}
    end
  end

  describe "HOLE: subject/1 failures are printed" do
    test "a failed subject lookup does not put its error term in the exception message" do
      failed = {:error, %{token: "tok_live_SECRET", email: "abby@example.com"}}

      error =
        assert_raise Warden.PolicyError, fn ->
          Warden.actor(%{current_user: failed}, authorizer: CoreAuthz)
        end

      refute error.message =~ "tok_live_SECRET"
      refute error.message =~ "abby@example.com"
    end
  end

  describe "held: bound credentials" do
    test "a bound credential cannot read another tenant's value through a role or a check" do
      key = %Credential{method: :api_key, scopes: :all, tenant: "t1"}
      staff = %{id: "staff", roles: [:staff]}
      foreign = %Doc{id: 1, tenant_id: "t2", open: true}
      bound = context(staff, %{credential: key})

      refute Warden.allowed?(bound, role(:staff), value: foreign, authorizer: CoreAuthz)
      refute Warden.allowed?(bound, check(:open), value: foreign, authorizer: CoreAuthz)
      refute Warden.allowed?(bound, authenticated(), value: foreign, authorizer: CoreAuthz)
      assert Warden.redact(bound, foreign, authorizer: CoreAuthz).body == "[hidden]"
      assert Warden.filter(bound, role(:staff), [foreign], authorizer: CoreAuthz) == []
    end

    test "deep redaction reaches a foreign-tenant struct nested in an own-tenant one" do
      key = %Credential{method: :api_key, scopes: :all, tenant: "t1"}
      staff = %{id: "staff", roles: [:staff]}
      foreign = %Doc{id: 2, tenant_id: "t2", body: "foreign body"}
      own = %Doc{id: 1, tenant_id: "t1", body: "own body", children: [foreign]}
      bound = context(staff, %{credential: key})

      redacted = Warden.redact(bound, own, authorizer: CoreAuthz, deep: true)

      assert redacted.body == "own body"
      assert [%Doc{body: "[hidden]"}] = redacted.children
    end
  end

  describe "held: delegation and system actors" do
    test "a system actor on behalf of staff gets no role grant" do
      staff = Warden.actor(context(%{id: "staff", roles: [:staff]}), authorizer: CoreAuthz)
      webhook = Warden.system_actor(CoreAuthz, kind: :webhook)

      refute Warden.allowed?(Warden.on_behalf_of(webhook, staff), role(:staff))
      refute Warden.allowed?(Warden.on_behalf_of(staff, webhook), role(:staff))
      refute Warden.allowed?(Warden.on_behalf_of(staff, webhook), authenticated())
    end

    test "all_permissions([]) and empty combinators are refused, not vacuously true" do
      webhook = Warden.system_actor(CoreAuthz, kind: :webhook)

      for rule <- [{:all_permissions, []}, {:any_role, []}, {:all, []}, {:any, []}] do
        assert_raise Warden.PolicyError, fn -> Warden.allowed?(webhook, rule) end
      end
    end

    test "an actor whose struct was rebuilt with another authorizer is refused" do
      staff = Warden.actor(context(%{id: "staff", roles: [:staff]}), authorizer: CoreAuthz)

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(staff, role(:staff), authorizer: Warden.Test.Authz)
      end
    end
  end
end
