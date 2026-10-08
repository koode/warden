defmodule Warden.ActorTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Warden.{Actor, Authorizer, Denial}
  alias Warden.Test.Authz

  defp build(user, extra \\ %{}), do: Actor.build(Authz, Map.merge(%{current_user: user}, extra))

  test "an anonymous actor has no roles or permissions and roles/2 is not called" do
    actor = build(nil, %{roles_fun: fn _ -> raise "must not be called" end})
    assert actor == %Actor{}
    assert Actor.anonymous?(actor)
  end

  test "the hierarchy is expanded" do
    actor = build(%{id: "a", roles: [:admin]})
    assert actor.roles == MapSet.new([:admin, :editor, :viewer])

    actor = build(%{id: "e", roles: [:editor]})
    assert actor.roles == MapSet.new([:editor, :viewer])
  end

  test "role_permissions are merged with permissions/2, :all kept as a marker" do
    actor = build(%{id: "e", roles: [:editor], permissions: ["secrets:read"]})
    assert actor.permissions == MapSet.new(["posts:write", "posts:read", "secrets:read"])

    admin = build(%{id: "a", roles: [:admin]})
    assert Actor.all_permissions?(admin)
    assert MapSet.member?(admin.permissions, :all)
  end

  test "unknown roles and permissions are dropped and logged, never granted" do
    log =
      capture_log(fn ->
        actor =
          build(%{id: "x", roles: [:viewer, :root], permissions: ["posts:read", "god", :all]})

        send(self(), {:actor, actor})
      end)

    assert_received {:actor, actor}
    assert actor.roles == MapSet.new([:viewer])
    assert actor.permissions == MapSet.new(["posts:read"])
    refute Actor.all_permissions?(actor)
    assert log =~ "[:root]"
    assert log =~ ~s(["god", :all])
  end

  test "callbacks must return lists" do
    assert_raise Warden.PolicyError, ~r/roles\/2 must return a list/, fn ->
      build(%{id: "x", roles: [:viewer]}, %{roles_fun: fn _ -> {:ok, [:admin]} end})
    end

    assert_raise Warden.PolicyError, ~r/permissions\/2 must return a list/, fn ->
      build(%{id: "x", roles: [], permissions: MapSet.new(["posts:read"])})
    end
  end

  describe "actor_key" do
    test "is deterministic and depends on subject identity, roles and permissions" do
      a1 = build(%{id: "1", roles: [:viewer]})
      a1b = build(%{id: "1", roles: [:viewer], name: "other"})
      a2 = build(%{id: "2", roles: [:viewer]})
      a3 = build(%{id: "1", roles: [:editor]})

      assert Authz.actor_key(a1) == Authz.actor_key(a1b)
      assert Authz.actor_key(a1) != Authz.actor_key(a2)
      assert Authz.actor_key(a1) != Authz.actor_key(a3)
      assert Authz.actor_key(%Actor{}) == Authz.actor_key(%Actor{})
      assert is_binary(Authz.actor_key(a1))
    end
  end

  describe "default_deny" do
    @catalog Authz.__warden_catalog__()

    test "says only Forbidden by default" do
      denial = %Denial{kind: :field, missing_roles: [:admin], missing_permissions: ["p"]}

      assert Authorizer.default_deny(denial, @catalog) ==
               {:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}
    end

    test "reveals reasons only when opted in" do
      denial = %Denial{kind: :field, missing_roles: [:admin], missing_permissions: ["p"]}

      assert {:error, %{extensions: %{missing_roles: ["admin"], missing_permissions: ["p"]}}} =
               Authorizer.default_deny(denial, %{@catalog | expose_denial_reasons: true})
    end

    test "spec-compliant errors put code at the top level for Absinthe to nest" do
      assert Authorizer.default_deny(%Denial{kind: :field}, %{
               @catalog
               | spec_compliant_errors: true
             }) ==
               {:error, %{message: "Forbidden", code: "FORBIDDEN"}}
    end

    test "filtered list items get :null" do
      assert Authorizer.default_deny(
               %Denial{kind: :object, list_policy: :filter, value_index: [0]},
               @catalog
             ) ==
               :null
    end
  end
end
