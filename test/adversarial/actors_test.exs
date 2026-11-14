defmodule Warden.Adversarial.ActorsTest do
  @moduledoc """
  Attacks on the 0.2 actor model: system actors posing as users, bound credentials used
  for another tenant, delegation used to widen access, and check results that look like
  grants. Each test is named after the attempt.
  """
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.V2.People

  alias Warden.Credential
  alias Warden.Test.Decisions
  alias Warden.Test.V2.Authz

  @tenant_doc %{tenant_id: "t1", owner_id: "abby"}

  defp allowed?(actor_or_context, rule, opts \\ []),
    do: Warden.allowed?(actor_or_context, rule, [authorizer: Authz] ++ opts)

  defp system(kind, opts \\ []), do: Warden.system_actor(Authz, [kind: kind] ++ opts)

  describe "a system actor posing as a user" do
    test "fails authenticated, role, tenant role, permission, session and scope rules" do
      for kind <- [:system, :webhook, :agent],
          rule <- [
            authenticated(),
            role(:instance_admin),
            any_role([:instance_admin, :staff]),
            permission("docs:export"),
            all_permissions(["docs:export"]),
            any_permission(["docs:export"]),
            tenant_role(:guest),
            tenant_role(:guest, tenant: {:arg, [:tenant]}),
            session(),
            credential_scope("docs:read")
          ] do
        actor = system(kind, tenant: "t1")

        refute allowed?(actor, rule, value: @tenant_doc, args: %{tenant: "t1"}),
               inspect({kind, rule})
      end
    end

    test "passes only the kind rules that name it" do
      assert allowed?(system(:webhook), kind(:webhook))
      assert allowed?(system(:webhook), kind([:user, :webhook]))
      refute allowed?(system(:webhook), kind(:user))
      refute allowed?(system(:webhook), kind(:system))
      refute allowed?(system(:webhook), kind(:anonymous))
    end

    test "reaches a check only when the check names its kind" do
      context = context(nil, %{plain: true, reasoned: true})

      for name <- [:plain, :reasoned, :mine, :slow] do
        refute Warden.allowed?(system(:webhook), check(name),
                 context: context,
                 value: @tenant_doc
               )
      end

      refute_received {:check, _name}
      assert Warden.allowed?(system(:webhook), check(:hooked), context: context)
      assert_received {:check, :hooked}
      refute Warden.allowed?(system(:system), check(:hooked), context: context)
    end

    test "a batched check is not asked about a system actor either" do
      docs = [%{visible: true}, %{visible: true}]
      assert Warden.filter(system(:webhook), check(:visible), docs, context: context(nil)) == []
      refute_received {:check_many, _name, _count}
    end

    test "any_of with public still passes; nothing else is ambient" do
      assert allowed?(system(:webhook), any_of([role(:staff), public()]))
      refute allowed?(system(:webhook), any_of([role(:staff), authenticated(), check(:plain)]))
    end
  end

  describe "a bound credential used for another tenant" do
    @key %Credential{method: :api_key, scopes: :all, tenant: "t2"}

    test "has no tenant roles there, and tenant_roles/3 is not called" do
      context = context(abby(), %{credential: @key})

      refute Warden.allowed?(context, tenant_role(:guest),
               authorizer: Authz,
               value: %{tenant_id: "t1"}
             )

      refute_received {:tenant_roles, _user, "t1"}

      assert Warden.allowed?(context, tenant_role(:guest),
               authorizer: Authz,
               value: %{tenant_id: "t2"}
             )
    end

    test "cannot reach another tenant through an argument either" do
      rule = tenant_role(:owner, tenant: {:arg, [:workspace]})
      context = context(abby(), %{credential: @key})
      refute Warden.allowed?(context, rule, authorizer: Authz, args: %{workspace: "t1"})
    end

    test "a system actor bound to a tenant behaves the same" do
      bound = system(:webhook, tenant: "t2")
      assert Warden.Actor.tenants(bound, %{}) == ["t2"]
      refute Warden.Actor.tenant_allowed?(bound, "t1")
    end
  end

  describe "delegation used to widen access" do
    test "an agent gets nothing its user lacks, and the user nothing the agent lacks" do
      agent = actor(olivia())
      delegated = Warden.on_behalf_of(agent, actor(sam()))

      refute allowed?(delegated, tenant_role(:admin), value: @tenant_doc)
      assert allowed?(delegated, tenant_role(:guest), value: @tenant_doc)
      refute allowed?(delegated, kind(:agent))
      assert allowed?(delegated, kind([:agent, :user]))

      admin_agent = Warden.on_behalf_of(actor(Map.put(admin(), :kind, :agent)), actor(sam()))
      refute allowed?(admin_agent, role(:instance_admin))

      refute allowed?(
               Warden.on_behalf_of(actor(sam()), actor(admin())),
               permission("docs:export")
             )
    end

    test "any_of cannot be split across the two actors" do
      delegated = Warden.on_behalf_of(actor(admin()), actor(sam()))
      rule = any_of([role(:instance_admin), tenant_role(:member)])
      assert allowed?(actor(admin()), rule, value: %{tenant_id: "t1"}) == true
      assert allowed?(actor(sam()), rule, value: %{tenant_id: "t1"}) == true
      assert allowed?(delegated, rule, value: %{tenant_id: "t1"})

      split = all_of([role(:instance_admin), tenant_role(:member)])
      refute allowed?(delegated, split, value: %{tenant_id: "t1"})
    end

    test "a system actor acting for a user keeps the system restrictions" do
      delegated = Warden.on_behalf_of(system(:webhook), actor(abby()))
      refute allowed?(delegated, tenant_role(:guest), value: @tenant_doc)
      refute allowed?(delegated, authenticated())
    end
  end

  describe "check results that look like grants" do
    @lookalikes [{:deny, :not_member}, :ok, {:ok, true}, "true", 1, [true], %{}, nil]

    test "never grant, inside any_of and all_of too" do
      for result <- @lookalikes,
          rule <- [
            check(:plain),
            any_of([deny(), check(:plain)]),
            all_of([public(), check(:plain)]),
            any_of([all_of([check(:plain)]), role(:staff)])
          ] do
        context = context(abby(), %{plain: result})

        granted =
          try do
            Warden.allowed?(context, rule, authorizer: Authz)
          rescue
            Warden.PolicyError -> false
          end

        refute granted, inspect({result, rule})
      end
    end

    test "a timed-out check denies with :unavailable, even when it would grant later" do
      context = context(abby(), %{sleep: 300, slow_result: true})
      assert {:error, denial} = Warden.authorize(context, check(:slow), authorizer: Authz)
      assert denial.reason == :unavailable
      refute Warden.allowed?(context, any_of([deny(), check(:slow)]), authorizer: Authz)
      assert Warden.allowed?(context(abby(), %{sleep: 0}), check(:slow), authorizer: Authz)
    end

    test "a timed check that returns a non-boolean fails closed" do
      context = context(abby(), %{sleep: 0, slow_result: :raise})

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(context, check(:slow), authorizer: Authz)
      end
    end
  end

  describe "reasons and actors never leak" do
    test "the default ForbiddenError message names no reason" do
      context = context(abby(), %{reasoned: {:deny, {:not_member, %{team: "team-crimson"}}}})

      error =
        assert_raise Warden.ForbiddenError, fn ->
          Warden.authorize!(context, check(:reasoned), authorizer: Authz)
        end

      assert error.message == "Forbidden"
      assert error.denial.reason == {:not_member, %{team: "team-crimson"}}
      refute inspect(error.denial) =~ "team-crimson"
      refute inspect(error.denial) =~ "abby"
      assert inspect(error.denial) =~ "reason: :not_member"
    end

    test "telemetry metadata holds no subject and no value" do
      Decisions.attach()
      secret_doc = %{tenant_id: "t1", owner_id: "abby", body: "doc-body-secret"}
      context = context(abby(), %{reasoned: {:deny, {:no, %{doc: secret_doc}}}})

      Warden.allowed?(context, all_of([tenant_role(:guest), check(:reasoned)]),
        authorizer: Authz,
        value: secret_doc
      )

      Warden.filter(context, check(:mine), [secret_doc], authorizer: Authz)

      for _event <- 1..2 do
        assert_received {:decision, _measurements, metadata}
        refute inspect(metadata, limit: :infinity) =~ "doc-body-secret"
        refute inspect(metadata, limit: :infinity) =~ "abby"
      end
    end
  end
end
