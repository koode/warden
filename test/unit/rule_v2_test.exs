defmodule Warden.RuleV2Test do
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.V2.People

  alias Warden.{Credential, Explanation, Rule}
  alias Warden.Test.Decisions
  alias Warden.Test.V2.Authz

  @catalog Authz.__warden_catalog__()

  defp authorize(actor, rule, opts \\ []), do: Warden.authorize(actor, rule, opts)

  defp authorize_as(user, extra, rule, opts \\ []),
    do: Warden.authorize(context(user, extra), rule, [authorizer: Authz] ++ opts)

  describe "builders" do
    test "produce plain terms" do
      assert covered() == :covered
      assert session() == :session
      assert tenant_role(:member) == {:tenant_role, :member, []}

      assert tenant_role(:member, tenant: {:arg, [:id]}) ==
               {:tenant_role, :member, [tenant: {:arg, [:id]}]}

      assert kind(:agent) == {:kind, [:agent]}
      assert kind([:agent, :user]) == {:kind, [:agent, :user]}
      assert credential_scope("docs:read") == {:credential_scope, "docs:read"}
    end
  end

  describe "validate/2" do
    test "accepts the new terms" do
      for rule <- [
            covered(),
            session(),
            tenant_role(:guest),
            tenant_role(:owner, tenant: :value),
            tenant_role(:owner, tenant: {:arg, [:input, :workspace_id]}),
            kind(:webhook),
            kind([:anonymous, :user]),
            credential_scope("docs:write"),
            any_of([session(), all_of([kind(:agent), credential_scope("docs:read")])])
          ] do
        assert Rule.validate(rule, @catalog) == :ok, inspect(rule)
      end
    end

    test "rejects bad shapes" do
      for rule <- [
            {:tenant_role, "owner", []},
            {:tenant_role, :owner, [tenant: :parent]},
            {:tenant_role, :owner, [tenant: {:arg, []}]},
            {:tenant_role, :owner, [tenant: {:arg, ["id"]}]},
            {:tenant_role, :owner, [scope: :x]},
            {:kind, []},
            {:kind, ["user"]},
            {:credential_scope, :read}
          ] do
        assert {:error, [_ | _]} = Rule.validate(rule), inspect(rule)
      end
    end

    test "checks the catalogs" do
      assert {:error, [unknown_role]} = Rule.validate(tenant_role(:viewer), @catalog)
      assert unknown_role =~ "tenant role :viewer is not in the authorizer's tenant role catalog"

      assert {:error, [no_catalog]} =
               Rule.validate(tenant_role(:member), Warden.Test.Authz.__warden_catalog__())

      assert no_catalog =~ "needs `tenant_roles:`"

      assert {:error, [unknown_kind]} = Rule.validate(kind(:robot), @catalog)
      assert unknown_kind =~ "kind :robot is not in the authorizer's `kinds:`"

      assert {:error, [unknown_scope]} = Rule.validate(credential_scope("admin"), @catalog)
      assert unknown_scope =~ ~s|credential scope "admin" is not in|
    end

    test "the core API refuses an unknown term and covered()" do
      assert_raise Warden.PolicyError, ~r/tenant role :viewer/, fn ->
        authorize(actor(abby()), tenant_role(:viewer))
      end

      assert_raise Warden.PolicyError, ~r/covered\(\) is only meaningful/, fn ->
        authorize(actor(abby()), any_of([role(:staff), covered()]))
      end
    end
  end

  describe "tenant_role/1,2" do
    test "uses the tenant of the value, after the hierarchy" do
      doc = %{tenant_id: "t1"}
      assert authorize(actor(abby()), tenant_role(:guest), value: doc) == :ok
      assert authorize(actor(sam()), tenant_role(:member), value: doc) == :ok
      assert {:error, _denial} = authorize(actor(sam()), tenant_role(:admin), value: doc)

      assert {:error, _denial} =
               authorize(actor(abby()), tenant_role(:member), value: %{tenant_id: "t2"})
    end

    test "or the tenant from an argument path" do
      rule = tenant_role(:owner, tenant: {:arg, [:input, :workspace_id]})
      assert authorize(actor(abby()), rule, args: %{input: %{workspace_id: "t1"}}) == :ok

      assert {:error, _denial} =
               authorize(actor(abby()), rule, args: %{input: %{workspace_id: "t2"}})

      assert {:error, _denial} = authorize(actor(abby()), rule, args: %{})
    end

    test "a value without a tenant denies" do
      for value <- [nil, %{}, %{tenant_id: nil}, "t1"] do
        assert {:error, _denial} = authorize(actor(abby()), tenant_role(:guest), value: value)
      end
    end

    test "reads the tenant roles once per call, across sub-rules and values" do
      rule = all_of([tenant_role(:guest), any_of([tenant_role(:owner), tenant_role(:admin)])])
      context = context(abby())
      assert Warden.authorize(context, rule, authorizer: Authz, value: %{tenant_id: "t1"}) == :ok
      assert_received {:tenant_roles, "abby", "t1"}
      refute_received {:tenant_roles, _user, _tenant}

      docs = [%{tenant_id: "t1"}, %{tenant_id: "t2"}, %{tenant_id: "t1"}, %{tenant_id: "t2"}]

      assert Warden.filter(context, tenant_role(:member), docs, authorizer: Authz) == [
               %{tenant_id: "t1"},
               %{tenant_id: "t1"}
             ]

      assert_received {:tenant_roles, "abby", "t1"}
      assert_received {:tenant_roles, "abby", "t2"}
      refute_received {:tenant_roles, _user, _tenant}
    end
  end

  describe "kind/1, session/0, credential_scope/1" do
    test "kind" do
      assert authorize(actor(olivia()), kind(:agent)) == :ok
      assert {:error, _denial} = authorize(actor(abby()), kind(:agent))
      assert authorize(Warden.actor(%{}, authorizer: Authz), kind(:anonymous)) == :ok
    end

    test "a session grants every scope; a scoped credential only its scopes" do
      assert authorize(actor(abby()), session()) == :ok
      assert authorize(actor(abby()), credential_scope("docs:write")) == :ok

      key = actor(abby(), %{credential: %Credential{method: :api_key, scopes: ["docs:read"]}})
      assert {:error, _denial} = authorize(key, session())
      assert authorize(key, credential_scope("docs:read")) == :ok
      assert {:error, _denial} = authorize(key, credential_scope("docs:write"))

      everything = actor(abby(), %{credential: %Credential{method: :oauth, scopes: :all}})
      assert authorize(everything, credential_scope("docs:write")) == :ok
    end

    test "an anonymous actor has no session and no scopes" do
      anonymous = Warden.actor(%{}, authorizer: Authz)
      assert {:error, _denial} = authorize(anonymous, session())
      assert {:error, _denial} = authorize(anonymous, credential_scope("docs:read"))
    end
  end

  describe "check reasons" do
    test "{:deny, reason} denies and carries the reason and the trace" do
      assert {:error, denial} = authorize(actor(abby()), check(:reasoned))
      assert denial.reason == :not_member
      assert denial.trace == [{{:check, :reasoned, []}, {:deny, :not_member}}]

      details = %{reasoned: {:deny, {:role_too_low, %{needed: :admin}}}}

      assert {:error, %{reason: {:role_too_low, %{needed: :admin}}}} =
               authorize_as(abby(), details, check(:reasoned))
    end

    test "any_of collects the reasons in rule order" do
      rule = any_of([check(:reasoned), role(:staff), check(:plain)])
      assert {:error, denial} = authorize(actor(abby()), rule)
      assert denial.reason == [:not_member, nil, nil]
      assert denial.failed_rule == rule
      assert [_first, _second, _third] = denial.trace
    end

    test "all_of reports the first failing reason" do
      rule = all_of([session(), check(:reasoned), check(:plain)])

      assert {:error, %{reason: :not_member, failed_rule: {:check, :reasoned, []}}} =
               authorize(actor(abby()), rule)
    end

    test "a bad reason or result raises" do
      for bad <- [{:deny, "text"}, {:deny, {:a, :b}}, {:deny, :a, :b}, :deny, {:ok, true}, nil] do
        assert_raise Warden.PolicyError, ~r/must return true or false/, fn ->
          authorize_as(abby(), %{reasoned: bad}, check(:reasoned))
        end
      end
    end
  end

  describe "explain/3" do
    test "evaluates every step without short-circuiting" do
      rule = any_of([session(), check(:reasoned)])

      assert %Explanation{result: :ok, steps: [step]} =
               Warden.explain(context(abby()), rule, authorizer: Authz)

      assert step.rule == rule

      assert [
               %{rule: :session, result: :ok},
               %{rule: {:check, :reasoned, []}, result: {:deny, :not_member}}
             ] = step.steps

      assert_received {:check, :reasoned}
    end

    test "its result always equals authorize/3" do
      rules = [
        session(),
        check(:reasoned),
        all_of([session(), check(:plain)]),
        any_of([check(:reasoned), tenant_role(:owner)]),
        any_of([role(:staff), all_of([kind(:user), tenant_role(:guest)])])
      ]

      actors = [
        actor(abby()),
        actor(sam()),
        actor(olivia()),
        Warden.system_actor(Authz, kind: :webhook)
      ]

      for rule <- rules,
          actor <- actors,
          value <- [%{tenant_id: "t1"}, %{tenant_id: "t2"}, nil] do
        decision = if authorize(actor, rule, value: value) == :ok, do: :ok, else: :deny
        assert Warden.explain(actor, rule, value: value).result == decision
      end
    end

    test "explains both actors of a delegation" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))
      explanation = Warden.explain(delegated, kind(:agent))
      assert explanation.result == :deny
      assert explanation.steps == [%{rule: {:kind, [:agent]}, result: :ok, steps: []}]
      assert %Explanation{result: :deny} = explanation.delegator
    end
  end

  describe "telemetry" do
    setup do
      Decisions.attach()
      :ok
    end

    test "one event per decision call, a list counted as one" do
      authorize(actor(abby()), check(:reasoned), value: %{tenant_id: "t1"})
      assert_received {:decision, %{count: 1, denied: 1}, metadata}

      assert metadata == %{
               layer: :core,
               kind: :call,
               rule: {:check, :reasoned, []},
               result: :deny,
               reason: :not_member,
               actor_kind: :user,
               tenant: nil
             }

      Warden.filter(actor(abby()), tenant_role(:member), [
        %{tenant_id: "t1"},
        %{tenant_id: "t2"},
        %{tenant_id: "t1"}
      ])

      assert_received {:decision, %{count: 3, denied: 1}, %{result: :deny}}
      refute_received {:decision, _measurements, _metadata}
    end

    test "reports the tenant a rule resolved, and the details of a reason never" do
      details = %{reasoned: {:deny, {:role_too_low, %{secret: "s3cr3t"}}}}

      authorize_as(abby(), details, all_of([tenant_role(:guest), check(:reasoned)]),
        value: %{tenant_id: "t1"}
      )

      assert_received {:decision, _measurements,
                       %{tenant: "t1", reason: :role_too_low} = metadata}

      refute inspect(metadata) =~ "s3cr3t"
    end
  end
end
