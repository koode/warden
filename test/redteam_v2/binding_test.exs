defmodule Warden.RedteamV2.BindingTest do
  # Security goal 11: a credential bound to tenant A denies every rule, policy and scope
  # for any other tenant, without calling user code.
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.RedteamV2.People

  alias Warden.RedteamV2.{Authz, Doc, DocPolicy}

  @doc_in_a %Doc{id: 1, workspace_id: "a", owner_id: "abby", body: "body in a"}
  @doc_in_b %Doc{id: 2, workspace_id: "b", owner_id: "abby", body: "body in b"}

  defp bound_actor(user, tenant), do: actor(user, %{credential: bound_credential(tenant)})

  defp drain(acc \\ []) do
    receive do
      message -> drain([message | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "holes: rules other than tenant roles and policies ignore the binding" do
    # HOLE: a check-based rule (the 0.1 way to guard a resource) passes for another
    # tenant's value, and the check (user code) is called with it.
    test "a check rule denies another tenant's value without calling the check" do
      api_key = bound_actor(abby(), "a")
      drain()

      refute Warden.allowed?(api_key, check(:owner), value: @doc_in_b, context: context(abby()))
      refute_received {:check, :owner, "b"}
    end

    # HOLE: a global permission lets a key bound to "a" filter in docs of "b".
    test "a permission rule does not admit another tenant's values in filter/4" do
      api_key = bound_actor(staff(), "a")

      assert Warden.filter(api_key, permission("docs:read"), [@doc_in_a, @doc_in_b]) == [
               @doc_in_a
             ]
    end

    # HOLE: the policy screens the bound tenant, but any_of next to a check reopens it.
    test "any_of with a check cannot reopen what the policy's binding screen closed" do
      api_key = bound_actor(abby(), "a")

      refute Warden.allowed?(api_key, can(DocPolicy, :read), value: @doc_in_b)

      refute Warden.allowed?(api_key, any_of([can(DocPolicy, :read), check(:owner)]),
               value: @doc_in_b
             )
    end

    # HOLE: a system actor bound to "a" whose kind a check names reaches docs of "b".
    test "a bound system actor gets no check grant for another tenant" do
      webhook = Warden.system_actor(Authz, kind: :webhook, tenant: "a")

      assert Warden.allowed?(webhook, check(:hooked), value: @doc_in_a, context: context(nil))
      refute Warden.allowed?(webhook, check(:hooked), value: @doc_in_b, context: context(nil))
    end

    # HOLE: the batched pass calls check_many/2 with every value before the per-value
    # short-circuit, so user code sees another tenant's values even though the
    # tenant_role leaf in front of it denies them (the single path never calls it).
    test "a batched check is not called with another tenant's values" do
      api_key = bound_actor(abby(), "a")
      rule = all_of([tenant_role(:member), check(:visible_many)])
      drain()

      assert Warden.filter(api_key, rule, [@doc_in_a, @doc_in_b], context: context(abby())) == [
               @doc_in_a
             ]

      assert_received {:check_many, :visible_many, tenants}
      assert tenants == ["a"]
    end
  end

  describe "holes: odd tenant values" do
    # LOW: a client argument that is a list or a map reaches tenant_roles/3 as the
    # tenant. Most lookups fail closed on it, but Warden passes it on unchecked.
    test "a non-scalar tenant from the arguments never reaches tenant_roles/3" do
      unbound = actor(abby())
      rule = tenant_role(:member, tenant: {:arg, [:tenant]})
      drain()

      context = context(abby())
      refute Warden.allowed?(unbound, rule, args: %{tenant: ["a", "b"]}, context: context)
      refute Warden.allowed?(unbound, rule, args: %{tenant: %{"id" => "a"}}, context: context)
      refute_received {:tenant_roles, "abby", ["a", "b"]}
      refute_received {:tenant_roles, "abby", %{"id" => "a"}}
    end
  end

  describe "defended: tenant roles, policies and argument tenants" do
    test "no tenant roles in another tenant, and tenant_roles/3 is not called" do
      api_key = bound_actor(abby(), "a")
      drain()

      context = context(abby())
      refute Warden.allowed?(api_key, tenant_role(:member), value: @doc_in_b, context: context)

      refute Warden.allowed?(api_key, tenant_role(:member, tenant: {:arg, [:tenant]}),
               args: %{tenant: "b"},
               context: context
             )

      refute_received {:tenant_roles, _user, "b"}
      assert Warden.allowed?(api_key, tenant_role(:owner), value: @doc_in_a)
    end

    test "an equal-looking tenant of another type does not match the binding" do
      api_key = actor(abby(), %{credential: bound_credential(1)})
      rule = tenant_role(:member, tenant: {:arg, [:tenant]})

      refute Warden.allowed?(api_key, rule, args: %{tenant: "1"})
      refute Warden.allowed?(api_key, rule, args: %{tenant: [1]})
      refute Warden.allowed?(api_key, rule, args: %{tenant: %{id: 1}})
    end

    test "the policy is never asked about another tenant or an id from arguments" do
      api_key = bound_actor(abby(), "a")
      docs = %{2 => @doc_in_b, 1 => @doc_in_a}
      drain()

      context = context(abby(), %{docs: docs})
      refute Warden.allowed?(api_key, can(DocPolicy, :read), value: @doc_in_b, context: context)

      refute Warden.allowed?(api_key, can(DocPolicy, :read, arg: [:id]),
               args: %{id: 1},
               context: context
             )

      assert Warden.filter(api_key, can(DocPolicy, :read), [@doc_in_a, @doc_in_b],
               context: context
             ) == [@doc_in_a]

      refute Enum.any?(drain(), &match?({:allowed?, :read, %Doc{workspace_id: "b"}}, &1))
    end

    test "tenants/2 is narrowed to the bound tenant" do
      api_key = bound_actor(abby(), "a")
      assert Warden.Actor.tenants(api_key, %{}) == ["a"]
    end

    test "the tenant-role cache is per actor: a bound actor never reuses another's entry" do
      unbound = actor(abby())
      {_roles, warmed} = Warden.Actor.tenant_roles(unbound, "b", %{})
      assert Map.has_key?(warmed.cache, {:tenant_roles, "b"})

      api_key = bound_actor(abby(), "a")
      refute Warden.allowed?(api_key, tenant_role(:member), value: @doc_in_b)
    end
  end
end
