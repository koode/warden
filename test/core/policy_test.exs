defmodule Warden.PolicyTest do
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.CompileHelpers
  import Warden.Test.V2.People

  alias Warden.Credential
  alias Warden.Test.V2.{Authz, Brittle, Doc, Docs}

  defp allowed?(actor_or_context, rule, opts \\ []),
    do: Warden.allowed?(actor_or_context, rule, [authorizer: Authz] ++ opts)

  defp asked do
    receive do
      {:allowed?, action} -> [{:one, action} | asked()]
      {:allowed_many, action, count} -> [{:many, action, count} | asked()]
    after
      0 -> []
    end
  end

  describe "can/2" do
    test "asks the policy about the value" do
      context = context(abby())
      assert allowed?(context, can(Docs, :read), value: Doc.get(1))
      assert allowed?(context, can(Docs, :read), value: Doc.get(5))
      refute allowed?(context, can(Docs, :read), value: Doc.get(2))
      refute allowed?(context, can(Docs, :write), value: Doc.get(5))

      assert asked() == [
               {:many, :read, 1},
               {:many, :read, 1},
               {:many, :read, 1},
               {:many, :write, 1}
             ]
    end

    test "a nil value denies without asking" do
      refute allowed?(context(abby()), can(Docs, :read))
      assert asked() == []
    end

    test "composes with other rules" do
      rule = any_of([role(:instance_admin), all_of([session(), can(Docs, :write)])])
      assert allowed?(context(admin()), rule, value: Doc.get(2))
      assert allowed?(context(sam()), rule, value: Doc.get(2))
      refute allowed?(context(abby()), rule, value: Doc.get(2))
    end

    test "the denial carries the policy's reason" do
      context = context(abby(), %{policy_result: {:deny, :archived}})

      assert {:error, denial} =
               Warden.authorize(context, can(Brittle, :read), authorizer: Authz, value: %{})

      assert denial.reason == :archived
    end
  end

  describe "can/3 with arg:" do
    test "asks about {schema, id} from the argument path" do
      rule = can(Docs, :write, arg: [:input, :id])
      assert allowed?(context(abby()), rule, args: %{input: %{id: 1}})
      refute allowed?(context(abby()), rule, args: %{input: %{id: 2}})
    end

    test "a list of ids must all be allowed; a missing or empty one denies" do
      rule = can(Docs, :write, arg: [:ids])
      assert allowed?(context(abby()), rule, args: %{ids: [1, 3]})
      refute allowed?(context(abby()), rule, args: %{ids: [1, 2]})
      refute allowed?(context(abby()), rule, args: %{ids: []})
      refute allowed?(context(abby()), rule, args: %{})
      refute allowed?(context(abby()), rule, args: %{ids: [nil]})
    end
  end

  describe "lists" do
    test "filter asks the policy once and keeps the order" do
      docs = Doc.all()

      assert Enum.map(
               Warden.filter(context(abby()), can(Docs, :read), docs, authorizer: Authz),
               & &1.id
             ) == [1, 3, 5]

      assert asked() == [{:many, :read, 5}]
    end

    test "every distinct policy and action is asked once" do
      rule = any_of([can(Docs, :write), all_of([can(Docs, :read), tenant_role(:member)])])
      result = Warden.filter(context(sam()), rule, Doc.all(), authorizer: Authz)
      assert Enum.map(result, & &1.id) == [2, 5]
      assert Enum.sort(asked()) == [{:many, :read, 5}, {:many, :write, 5}]
    end

    test "a policy without allowed_many/4 is asked value by value" do
      context = context(abby(), %{policy_result: true})

      assert Warden.filter(context, can(Brittle, :read), [%{}, %{}], authorizer: Authz) == [
               %{},
               %{}
             ]
    end
  end

  describe "who reaches the policy" do
    test "system actors only of the policy's system_kinds" do
      webhook = Warden.system_actor(Authz, kind: :webhook)
      context = context(nil)

      assert Warden.filter(webhook, can(Docs, :read), Doc.all(), context: context)
             |> Enum.map(& &1.id) == [3, 5]

      assert asked() == [{:many, :read, 5}]

      system = Warden.system_actor(Authz, kind: :system)
      assert Warden.filter(system, can(Docs, :read), Doc.all(), context: context) == []
      assert asked() == []
    end

    test "a bound credential is never asked about another tenant" do
      key = %Credential{method: :api_key, scopes: :all, tenant: "t2"}
      context = context(abby(), %{credential: key})

      assert Warden.filter(context, can(Docs, :read), Doc.all(), authorizer: Authz)
             |> Enum.map(& &1.id) == [3]

      assert asked() == [{:many, :read, 2}]
    end

    test "a bound credential cannot use ids, whose tenant Warden cannot see" do
      key = %Credential{method: :api_key, scopes: :all, tenant: "t1"}
      context = context(abby(), %{credential: key})
      refute allowed?(context, can(Docs, :write, arg: [:id]), args: %{id: 1})
      assert asked() == []
    end

    test "a delegated actor needs both actors allowed" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))
      context = context(nil)
      # Olivia reads public docs and her own (4, 5); Abby reads public docs and hers (1, 3, 5).
      assert Warden.filter(delegated, can(Docs, :read), Doc.all(), context: context)
             |> Enum.map(& &1.id) == [3, 5]

      refute Warden.allowed?(delegated, can(Docs, :write), value: Doc.get(1), context: context)
    end
  end

  describe "broken policies fail closed" do
    for {label, result} <- [
          {"a non-boolean", :ok},
          {"{:ok, true}", {:ok, true}},
          {"a bad reason", {:deny, "text"}},
          {"nil", nil}
        ] do
      test "#{label} raises" do
        context = context(abby(), %{policy_result: unquote(Macro.escape(result))})

        for rule <- [can(Brittle, :read), any_of([deny(), can(Brittle, :read)])] do
          assert_raise Warden.PolicyError, fn -> allowed?(context, rule, value: %{}) end
        end
      end
    end

    test "a raise becomes a PolicyError" do
      context = context(abby(), %{policy_result: fn -> raise "boom" end})

      assert_raise Warden.PolicyError, ~r/failed deciding :read/, fn ->
        allowed?(context, can(Brittle, :read), value: %{})
      end
    end

    test "allowed_many/4 with a wrong length or a bad element raises" do
      for many <- [
            fn values -> tl(values) |> Enum.map(fn _value -> true end) end,
            fn values -> Enum.map(values, fn _value -> 1 end) end
          ] do
        context = context(abby(), %{policy_many: many})

        assert_raise Warden.PolicyError, fn ->
          Warden.filter(context, can(Docs, :read), Doc.all(), authorizer: Authz)
        end
      end
    end
  end

  describe "validation" do
    test "an unknown action or an unlisted policy raises in the core API" do
      assert_raise Warden.PolicyError, ~r/has no action :delete/, fn ->
        allowed?(context(abby()), can(Docs, :delete))
      end

      assert_raise Warden.PolicyError, ~r/is not in the authorizer's `policies:`/, fn ->
        allowed?(context(abby()), can(String, :read))
      end

      assert_raise Warden.PolicyError, ~r/only takes the option `arg:`/, fn ->
        allowed?(context(abby()), can(Docs, :read, id: 1))
      end

      assert_raise Warden.PolicyError, ~r/`arg:` must be a path/, fn ->
        allowed?(context(abby()), can(Docs, :read, arg: []))
      end
    end

    test "a policy of another authorizer is refused" do
      assert_raise Warden.PolicyError, ~r/is not in the authorizer's `policies:`/, fn ->
        Warden.allowed?(%{current_user: %{id: "x", roles: []}}, can(Docs, :read),
          authorizer: Warden.Test.Authz
        )
      end
    end

    test "use Warden.Policy validates its options" do
      for {opts, message} <- [
            {"authorizer: Warden.Test.V2.Authz, for: X, actions: [:read]",
             ~r/does not list .* in its `policies:`/},
            {"authorizer: String, for: X, actions: [:read]",
             ~r/does not `use Warden.Authorizer`/},
            {"authorizer: Warden.Test.V2.Authz, for: X, actions: []",
             ~r/`:actions` must be a non-empty list/},
            {"authorizer: Warden.Test.V2.Authz, for: X, actions: [:a, :a]",
             ~r/`:actions` contains duplicates/},
            {"authorizer: Warden.Test.V2.Authz, actions: [:read]", ~r/`:for` .* is required/},
            {"authorizer: Warden.Test.V2.Authz, for: X, actions: [:read], system_kinds: [:user]",
             ~r/`:system_kinds` names :user/},
            {"authorizer: Warden.Test.V2.Authz, for: X, actions: [:read], scope: true",
             ~r/unknown options: \[:scope\]/}
          ] do
        assert_raise CompileError, message, fn ->
          compile!("""
          defmodule #{unique("Warden.Test.Compiled.Policy")} do
            use Warden.Policy, #{opts}
            def allowed?(_action, _actor, _value, _context), do: true
          end
          """)
        end
      end
    end

    test "a policy must define allowed?/4" do
      authorizer = unique("Warden.Test.Compiled.PolicyAuthz")
      policy = unique("Warden.Test.Compiled.Unwritten")

      assert_raise CompileError, ~r/does not define allowed\?\/4/, fn ->
        compile!("""
        defmodule #{authorizer} do
          use Warden.Authorizer, roles: [:a], policies: [#{policy}]
          def subject(context), do: context[:user]
          def roles(_user, _context), do: []
        end

        defmodule #{policy} do
          use Warden.Policy, authorizer: #{authorizer}, for: X, actions: [:read]
        end
        """)
      end
    end
  end

  describe "tenant_of default" do
    test "uses the tenant: field of the policy registered for the struct" do
      assert allowed?(context(sam()), tenant_role(:member), value: Doc.get(2))
      refute allowed?(context(sam()), tenant_role(:member), value: Doc.get(4))
      assert Warden.Policy.policy_for(Authz, Doc.get(1)) == Docs
      assert Warden.Policy.policy_for(Authz, Doc) == Docs
      assert Warden.Policy.policy_for(Authz, %{}) == nil
    end
  end
end
