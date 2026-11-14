defmodule Warden.RedteamV2.DelegationTest do
  # Security goal 10: an actor acting on behalf of another gets the AND of both actors'
  # decisions, inside explicit bounds. Nothing may come out wider than either actor.
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.RedteamV2.People

  alias Warden.RedteamV2.{Authz, Comment, Doc, DocPolicy}

  @olivia_doc %Doc{id: 7, workspace_id: "a", owner_id: "olivia", body: "olivia's"}
  @abby_doc %Doc{id: 8, workspace_id: "a", owner_id: "abby", body: "abby's"}
  @public_doc %Doc{id: 9, workspace_id: "a", owner_id: "sam", public: true}

  describe "holes" do
    # HOLE: on_behalf_of/3 merges its bounds over the agent credential's bounds, so a
    # delegation call replaces the limit the agent's own key carries. The agent's key is
    # limited to doc 8; delegating with bounds for doc 9 lets the agent read doc 9,
    # which the agent's key alone may not.
    test "delegation bounds cannot replace the bounds of the agent's own credential" do
      key = %Warden.Credential{method: :api_key, scopes: :all, bounds: %{doc_ids: [8]}}
      agent = actor(olivia(), %{credential: key})
      user = actor(abby())

      refute Warden.allowed?(agent, can(DocPolicy, :read), value: @public_doc)
      assert Warden.allowed?(user, can(DocPolicy, :read), value: @public_doc)

      delegated = Warden.on_behalf_of(agent, user, bounds: %{doc_ids: [9]})

      refute Warden.allowed?(delegated, can(DocPolicy, :read), value: @public_doc)
    end

    # HOLE (latent until scopes use it): tenants/2 of a delegated actor lists the
    # agent's tenants, not the ones both actors share.
    test "tenants/2 of a delegated actor lists only tenants both actors have" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(sam()))

      assert Warden.Actor.tenants(delegated, %{}) == ["a"]
    end

    # LOW: the delegator's pass gets the agent's context, so a check that reads the
    # user from the context (the 0.1 `context[:current_user]` habit) evaluates the
    # agent twice: Sam's own decision is never asked.
    test "the delegator's checks do not see the agent's context as their own" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(sam()))
      context = context(olivia())

      refute Warden.allowed?(actor(sam()), check(:context_owner),
               value: @olivia_doc,
               context: context(sam())
             )

      refute Warden.allowed?(delegated, check(:context_owner),
               value: @olivia_doc,
               context: context
             )
    end
  end

  describe "defended" do
    test "a single rule, filter/4, explain/3 and redaction are all the AND of both" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))
      context = context(olivia())
      docs = [@olivia_doc, @abby_doc]

      refute Warden.allowed?(delegated, check(:owner), value: @olivia_doc, context: context)
      refute Warden.allowed?(delegated, check(:owner), value: @abby_doc, context: context)
      assert Warden.filter(delegated, check(:owner), docs, context: context) == []
      assert Warden.filter(delegated, can(DocPolicy, :write), docs, context: context) == []

      assert Warden.explain(delegated, check(:owner), value: @abby_doc, context: context).result ==
               :deny

      comments = [
        %Comment{id: 1, owner_id: "olivia", body: "olivia's comment"},
        %Comment{id: 2, owner_id: "abby", body: "abby's comment"}
      ]

      assert [%Comment{body: "[hidden]"}, %Comment{body: "[hidden]"}] =
               Warden.redact(delegated, comments, context: context)
    end

    test "any_of cannot pass the agent on one branch and the user on another" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))
      rule = any_of([check(:owner), tenant_role(:owner)])

      # Olivia passes nothing but her own doc; Abby owns "a" but not Olivia's doc.
      refute Warden.allowed?(delegated, rule, value: @abby_doc, context: context(olivia()))
    end

    test "nesting, anonymous delegators and mixed authorizers are refused" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(sam()))
      anonymous = Warden.actor(%{}, authorizer: Authz)

      other =
        Warden.actor(%{current_user: %{id: "abby", roles: []}}, authorizer: Warden.Test.V2.Authz)

      assert_raise ArgumentError, fn -> Warden.on_behalf_of(delegated, actor(abby())) end
      assert_raise ArgumentError, fn -> Warden.on_behalf_of(actor(abby()), delegated) end
      assert_raise ArgumentError, fn -> Warden.on_behalf_of(actor(abby()), anonymous) end
      assert_raise ArgumentError, fn -> Warden.on_behalf_of(actor(abby()), other) end
    end

    test "a delegated actor's kind rule needs both kinds" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(sam()))

      refute Warden.allowed?(delegated, kind(:agent))
      assert Warden.allowed?(delegated, kind([:agent, :user]))
    end
  end
end
