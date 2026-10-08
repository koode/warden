defmodule Warden.RuleTest do
  use ExUnit.Case, async: true

  import Warden.Rule
  alias Warden.{Actor, Check, Rule}
  alias Warden.Test.Authz

  defp actor(roles, perms \\ [], subject \\ %{id: "me"}) do
    %Actor{subject: subject, roles: MapSet.new(roles), permissions: MapSet.new(perms)}
  end

  defp eval(rule, actor, extra \\ []) do
    Rule.evaluate(rule, struct!(Check, [actor: actor] ++ extra), Authz)
  end

  describe "builders" do
    test "produce plain terms" do
      assert public() == :public
      assert authenticated() == :authenticated
      assert deny() == :deny
      assert role(:a) == {:role, :a}
      assert any_role([:a, :b]) == {:any_role, [:a, :b]}
      assert permission("p") == {:permission, "p"}
      assert all_permissions(["p"]) == {:all_permissions, ["p"]}
      assert any_permission(["p"]) == {:any_permission, ["p"]}
      assert check(:c) == {:check, :c, []}
      assert check(:c, x: 1) == {:check, :c, [x: 1]}
      assert all_of([public()]) == {:all, [:public]}
      assert any_of([public()]) == {:any, [:public]}
    end
  end

  describe "validate/2" do
    @catalog Authz.__warden_catalog__()

    test "accepts valid rules" do
      for rule <- [
            public(),
            authenticated(),
            deny(),
            role(:admin),
            any_role([:admin, :viewer]),
            permission("posts:read"),
            all_permissions(["posts:read", "posts:write"]),
            any_permission(["posts:read"]),
            check(:self),
            check(:owner, strict: true),
            all_of([role(:admin), any_of([check(:self), permission("posts:read")])])
          ] do
        assert Rule.validate(rule, @catalog) == :ok, inspect(rule)
      end
    end

    test "rejects bad shapes" do
      for rule <- [
            :admin,
            {:role, "admin"},
            {:role, nil},
            {:any_role, []},
            {:all, []},
            {:any, []},
            {:all_permissions, []},
            {:permission, nil},
            {:permission, :all},
            {:check, "self", []},
            {:check, :self, [1]},
            {:not, role(:admin)},
            true,
            nil
          ] do
        assert {:error, [_ | _]} = Rule.validate(rule), inspect(rule)
      end
    end

    test "checks catalog membership" do
      assert {:error, [msg]} = Rule.validate(role(:ghost), @catalog)
      assert msg =~ "role :ghost is not in the authorizer's role catalog"
      assert {:error, [_]} = Rule.validate(permission("nope"), @catalog)
      assert {:error, [_]} = Rule.validate(check(:nope), @catalog)
      assert {:error, [_, _]} = Rule.validate(any_of([role(:x), role(:y)]), @catalog)
    end

    test "permissions are free-form when the catalog has none" do
      assert Rule.validate(permission("anything"), %{@catalog | permissions: nil}) == :ok
    end
  end

  describe "evaluate/3" do
    test "public, deny, authenticated" do
      assert eval(public(), actor([])) == :ok
      assert {:deny, %{failed_rule: :deny}} = eval(deny(), actor([:admin], [:all]))
      assert eval(authenticated(), actor([])) == :ok
      assert {:deny, _} = eval(authenticated(), %Actor{})
    end

    test "roles report what is missing" do
      assert eval(role(:admin), actor([:admin])) == :ok
      assert {:deny, %{missing_roles: [:admin]}} = eval(role(:admin), actor([:viewer]))
      assert eval(any_role([:admin, :viewer]), actor([:viewer])) == :ok

      assert {:deny, %{missing_roles: [:admin, :editor]}} =
               eval(any_role([:admin, :editor]), actor([]))
    end

    test "permissions and the :all marker" do
      assert eval(permission("p"), actor([], ["p"])) == :ok
      assert eval(permission("p"), actor([], [:all])) == :ok
      assert {:deny, %{missing_permissions: ["p"]}} = eval(permission("p"), actor([], ["q"]))

      assert {:deny, %{missing_permissions: ["b"]}} =
               eval(all_permissions(["a", "b"]), actor([], ["a"]))

      assert eval(any_permission(["a", "b"]), actor([], ["b"])) == :ok
    end

    test ":all does not grant roles" do
      assert {:deny, _} = eval(role(:admin), actor([], [:all]))
    end

    test "all_of stops at the first failure and reports it" do
      rule = all_of([role(:viewer), permission("p"), role(:admin)])

      assert {:deny, %{failed_rule: {:permission, "p"}, missing_permissions: ["p"]}} =
               eval(rule, actor([:viewer]))
    end

    test "any_of reports the any rule and the union of what is missing" do
      rule = any_of([role(:admin), permission("p")])

      assert {:deny, %{failed_rule: ^rule, missing_roles: [:admin], missing_permissions: ["p"]}} =
               eval(rule, actor([]))

      assert eval(rule, actor([], ["p"])) == :ok
    end

    test "checks get the value and opts; only true grants" do
      assert eval(check(:self), actor([]), value: %{id: "me"}) == :ok

      assert {:deny, %{failed_rule: {:check, :self, []}}} =
               eval(check(:self), actor([]), value: %{id: "x"})

      for bad <- [:ok, {:ok, true}, "yes", 1, nil, [], "true"] do
        assert_raise Warden.PolicyError, ~r/must return true or false/, fn ->
          eval(check(:configured), actor([]), context: %{check_result: bad})
        end
      end
    end

    test "any_of short-circuits before a check that would raise" do
      rule = any_of([role(:admin), check(:configured)])
      assert eval(rule, actor([:admin]), context: %{check_result: :boom}) == :ok
    end

    test "an invalid rule term raises" do
      assert_raise Warden.PolicyError, fn -> eval({:not, :public}, actor([])) end
    end
  end

  describe "Warden.authorize/4" do
    test "evaluates outside of an execution" do
      ctx = %{current_user: %{id: "u1", roles: [:admin]}}
      assert Warden.authorize(Authz, permission("secrets:read"), ctx) == :ok
      assert {:deny, _} = Warden.authorize(Authz, role(:admin), %{current_user: nil})

      assert Warden.authorize(Authz, check(:self), %{current_user: %{id: "u1", roles: []}}, %{
               id: "u1"
             }) == :ok
    end
  end
end
