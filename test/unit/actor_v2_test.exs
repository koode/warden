defmodule Warden.ActorV2Test do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Warden.Test.V2.People

  alias Warden.{Actor, Authorizer, Credential}
  alias Warden.Test.V2.Authz

  defp received_tenant_roles do
    receive do
      {:tenant_roles, user_id, tenant} -> [{user_id, tenant} | received_tenant_roles()]
    after
      0 -> []
    end
  end

  describe "kind" do
    test "defaults to :user, comes from kind/2, and is :anonymous without a subject" do
      assert actor(abby()).kind == :user
      assert Actor.kind(actor(olivia())) == :agent
      anonymous = Warden.actor(%{}, authorizer: Authz)
      assert Actor.kind(anonymous) == :anonymous
      assert Actor.anonymous?(anonymous)
    end

    test "an undeclared kind raises" do
      for bad <- [:robot, :anonymous, "user", nil] do
        assert_raise Warden.PolicyError, ~r/kind\/2 returned/, fn ->
          actor(Map.put(abby(), :kind, bad))
        end
      end
    end

    test "hand-built actors get a kind from their subject" do
      assert Actor.kind(%Actor{subject: %{id: 1}}) == :user
      assert Actor.kind(%Actor{}) == :anonymous
    end
  end

  describe "credential" do
    test "nil is a full session" do
      assert actor(abby()).credential == nil
      assert Credential.session?(nil)
      assert Credential.grants?(nil, "docs:write")
    end

    test "scopes outside the catalog are dropped with a warning" do
      credential = %Credential{method: :api_key, scopes: ["docs:read", "admin:all"]}

      log =
        capture_log(fn ->
          assert actor(abby(), %{credential: credential}).credential.scopes == ["docs:read"]
        end)

      assert log =~ "admin:all"
    end

    test "a bad credential raises" do
      for bad <- [
            %{method: :api_key},
            :session,
            %Credential{method: nil},
            %Credential{scopes: [:read]}
          ] do
        assert_raise Warden.PolicyError, ~r/credential\/1/, fn ->
          actor(abby(), %{credential: bad})
        end
      end
    end

    test "the credential bounds become the actor's bounds" do
      credential = %Credential{method: :api_key, scopes: [], bounds: %{team_ids: [1]}}
      assert actor(abby(), %{credential: credential}).bounds == %{team_ids: [1]}
    end

    test "callbacks are not called for an anonymous actor" do
      anonymous = Warden.actor(%{credential: :not_called}, authorizer: Authz)
      assert anonymous.credential == nil
    end
  end

  describe "tenant roles" do
    test "are read once per actor and tenant, then cached in the struct" do
      actor = actor(abby())
      {roles, actor} = Actor.tenant_roles(actor, "t1", context(abby()))
      assert roles == MapSet.new([:owner, :admin, :member, :guest])
      {^roles, actor} = Actor.tenant_roles(actor, "t1", context(abby()))
      {guest, _actor} = Actor.tenant_roles(actor, "t2", context(abby()))
      assert guest == MapSet.new([:guest])
      assert received_tenant_roles() == [{"abby", "t1"}, {"abby", "t2"}]
    end

    test "a fresh actor starts with an empty cache" do
      {_roles, cached} = Actor.tenant_roles(actor(abby()), "t1", context(abby()))
      assert cached.cache != %{}
      assert actor(abby()).cache == %{}
    end

    test "a bound credential has no tenant roles elsewhere and the callback is not called" do
      credential = %Credential{method: :api_key, scopes: :all, tenant: "t2"}
      actor = actor(abby(), %{credential: credential})
      assert {roles, _actor} = Actor.tenant_roles(actor, "t1", context(abby()))
      assert roles == MapSet.new()
      assert {guest, _actor} = Actor.tenant_roles(actor, "t2", context(abby()))
      assert guest == MapSet.new([:guest])
      assert received_tenant_roles() == [{"abby", "t2"}]
    end

    test "unknown tenant roles are dropped, a non-list raises" do
      context = context(abby(), %{tenant_roles_fun: fn _user, _tenant -> [:member, :ghost] end})

      log =
        capture_log(fn ->
          {roles, _actor} = Actor.tenant_roles(actor(abby()), "t1", context)
          assert roles == MapSet.new([:member, :guest])
        end)

      assert log =~ ":ghost"

      bad = context(abby(), %{tenant_roles_fun: fn _user, _tenant -> {:ok, [:owner]} end})

      assert_raise Warden.PolicyError, ~r/tenant_roles\/3 must return a list/, fn ->
        Actor.tenant_roles(actor(abby()), "t1", bad)
      end
    end

    test "anonymous and system actors and a nil tenant have none, without a call" do
      anonymous = Warden.actor(context(nil), authorizer: Authz)
      system = Warden.system_actor(Authz, kind: :webhook, tenant: "t1")

      for actor <- [anonymous, system] do
        assert {roles, _actor} = Actor.tenant_roles(actor, "t1", context(abby()))
        assert roles == MapSet.new()
      end

      assert {roles, _actor} = Actor.tenant_roles(actor(abby()), nil, context(abby()))
      assert roles == MapSet.new()
      assert received_tenant_roles() == []
    end

    test "preload_tenant_roles warms the cache" do
      actor = Actor.preload_tenant_roles(actor(abby()), ["t1", "t2"], context(abby()))
      assert received_tenant_roles() == [{"abby", "t1"}, {"abby", "t2"}]
      Actor.tenant_roles(actor, "t2", context(abby()))
      assert received_tenant_roles() == []
    end
  end

  describe "tenants" do
    test "come from tenants/2, narrowed by a bound credential" do
      assert Enum.sort(Actor.tenants(actor(abby()), %{})) == ["t1", "t2"]
      bound = actor(abby(), %{credential: %Credential{method: :api_key, tenant: "t2"}})
      assert Actor.tenants(bound, %{}) == ["t2"]
      elsewhere = actor(sam(), %{credential: %Credential{method: :api_key, tenant: "t2"}})
      assert Actor.tenants(elsewhere, %{}) == []
    end

    test "system and anonymous actors" do
      assert Actor.tenants(Warden.system_actor(Authz, kind: :webhook, tenant: "t1"), %{}) == [
               "t1"
             ]

      assert Actor.tenants(Warden.system_actor(Authz, kind: :webhook), %{}) == []
      assert Actor.tenants(Warden.actor(%{}, authorizer: Authz), %{}) == []
    end
  end

  describe "system_actor/2" do
    test "is never anonymous and never a user" do
      actor =
        Warden.system_actor(Authz,
          kind: :webhook,
          tenant: "t1",
          bounds: %{team_ids: [1]},
          reason: :delivery
        )

      assert actor.system?
      assert actor.subject == nil
      refute Actor.anonymous?(actor)
      assert Actor.kind(actor) == :webhook
      assert actor.roles == MapSet.new()
      assert actor.permissions == MapSet.new()
      assert actor.bounds == %{team_ids: [1]}
      assert actor.credential.method == :system
      assert actor.credential.reason == :delivery
      assert Actor.bound_tenant(actor) == "t1"
      refute Credential.session?(actor.credential)
      refute Credential.grants?(actor.credential, "docs:read")
    end

    test "needs a declared kind other than :user" do
      for kind <- [:user, :anonymous, :robot, nil] do
        assert_raise ArgumentError, ~r/needs `kind:`/, fn ->
          Warden.system_actor(Authz, kind: kind)
        end
      end

      assert_raise ArgumentError, ~r/unknown/, fn ->
        Warden.system_actor(Authz, kind: :webhook, roles: [:x])
      end
    end

    test "uses the configured default authorizer when given nil" do
      assert_raise ArgumentError, ~r/needs `kind:`/, fn ->
        Warden.system_actor(nil, kind: :webhook)
      end
    end
  end

  describe "on_behalf_of/3" do
    test "keeps the delegator and merges bounds" do
      actor = Warden.on_behalf_of(actor(olivia()), actor(abby()), bounds: %{doc_ids: [1]})
      assert actor.delegator.subject.id == "abby"
      assert actor.bounds == %{doc_ids: [1]}
    end

    test "refuses anonymous, foreign and nested delegation" do
      anonymous = Warden.actor(%{}, authorizer: Authz)

      foreign =
        Warden.actor(%{current_user: %{id: "x", roles: []}}, authorizer: Warden.Test.Authz)

      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))

      for {actor, delegator} <- [
            {anonymous, actor(abby())},
            {actor(olivia()), anonymous},
            {actor(olivia()), foreign},
            {delegated, actor(sam())},
            {actor(sam()), delegated}
          ] do
        assert_raise ArgumentError, fn -> Warden.on_behalf_of(actor, delegator) end
      end
    end

    test "a system actor may act on behalf of a user" do
      system = Warden.system_actor(Authz, kind: :system)
      assert Warden.on_behalf_of(system, actor(abby())).delegator
    end
  end

  describe "instance" do
    test "is new for every built, system and delegated actor" do
      user = actor(abby())
      agent = actor(olivia())
      system = Warden.system_actor(Authz, kind: :webhook)
      delegated = Warden.on_behalf_of(agent, user)

      instances = [
        user.instance,
        actor(abby()).instance,
        Warden.actor(%{}, authorizer: Authz).instance,
        agent.instance,
        system.instance,
        delegated.instance,
        delegated.delegator.instance
      ]

      assert Enum.all?(instances, &is_reference/1)
      assert instances == Enum.uniq(instances)
      assert delegated.delegator.subject == user.subject
    end

    test "is kept by the cache updates of the same actor" do
      user = actor(abby())
      {_roles, cached} = Actor.tenant_roles(user, "t1", context(abby()))
      {_tenants, listed} = Actor.cached_tenants(cached, context(abby()))
      assert listed.instance == user.instance

      delegated = Warden.on_behalf_of(actor(olivia()), user)
      {_tenants, both} = Actor.cached_tenants(delegated, context(abby()))
      assert both.instance == delegated.instance
      assert both.delegator.instance == delegated.delegator.instance
    end

    test "is not in inspect output or the actor key" do
      user = actor(abby())
      refute inspect(user) =~ "#Reference"
      assert Authorizer.default_actor_key(user) == Authorizer.default_actor_key(actor(abby()))
    end
  end

  describe "inspect" do
    test "shows kind, credential method and scopes and the delegator's kind, never a subject or bounds" do
      credential = %Credential{
        method: :api_key,
        scopes: ["docs:read"],
        tenant: "t1",
        bounds: %{secret_team: "team-crimson"}
      }

      user = actor(abby(), %{credential: credential})
      delegated = Warden.on_behalf_of(actor(olivia()), user, bounds: %{doc_ids: ["doc-9"]})
      system = Warden.system_actor(Authz, kind: :webhook, bounds: %{hook: "hook-secret"})

      for actor <- [user, delegated, system] do
        output = inspect(actor)
        refute output =~ "abby"
        refute output =~ "olivia"
        refute output =~ "team-crimson"
        refute output =~ "doc-9"
        refute output =~ "hook-secret"
        refute output =~ "t1"
      end

      assert inspect(user) =~ "method: :api_key"
      assert inspect(user) =~ ~s|scopes: ["docs:read"]|
      assert inspect(delegated) =~ "delegator: :user"
      assert inspect(delegated) =~ "kind: :agent"
      assert inspect(system) =~ "system?: true"
      refute inspect(credential) =~ "team-crimson"
      assert inspect(credential) =~ "bound: true"
    end
  end

  describe "default_actor_key/1" do
    test "keeps the 0.1 key for plain user actors" do
      plain = actor(%{id: "abby", roles: [:staff]})
      key_term = {{:id, "abby"}, [:staff], []}

      expected =
        key_term
        |> :erlang.term_to_binary([:deterministic])
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.url_encode64(padding: false)

      assert Authorizer.default_actor_key(plain) == expected
    end

    test "differs by kind, credential scopes, tenant, bounds, system and delegator" do
      key = &Authorizer.default_actor_key/1
      base = actor(abby())
      scoped = actor(abby(), %{credential: %Credential{method: :api_key, scopes: ["docs:read"]}})

      wider =
        actor(abby(), %{
          credential: %Credential{method: :api_key, scopes: ["docs:read", "docs:write"]}
        })

      bound =
        actor(abby(), %{
          credential: %Credential{method: :api_key, scopes: ["docs:read"], tenant: "t1"}
        })

      bounded =
        actor(abby(), %{
          credential: %Credential{method: :api_key, scopes: ["docs:read"], bounds: %{a: 1}}
        })

      agent = actor(Map.put(abby(), :kind, :agent))
      for_sam = Warden.on_behalf_of(agent, actor(sam()))
      for_abby = Warden.on_behalf_of(agent, actor(abby()))
      webhook = Warden.system_actor(Authz, kind: :webhook)
      system = Warden.system_actor(Authz, kind: :system)

      keys =
        Enum.map(
          [base, scoped, wider, bound, bounded, agent, for_sam, for_abby, webhook, system],
          key
        )

      assert length(Enum.uniq(keys)) == length(keys)

      assert key.(scoped) ==
               key.(
                 actor(abby(), %{credential: %Credential{method: :api_key, scopes: ["docs:read"]}})
               )
    end
  end
end
