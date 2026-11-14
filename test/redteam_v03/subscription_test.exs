defmodule Warden.RedteamV03.SubAuthz do
  @moduledoc false
  # Roles come from an Agent named in the context when there is one, so a test can
  # revoke a role between subscribe and publish.
  use Warden.Authorizer,
    roles: [:staff],
    tenant_roles: [:member]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, context) do
    case context[:roles] do
      nil -> Map.get(user, :roles, [])
      agent -> Agent.get(agent, & &1)
    end
  end

  @impl true
  def tenant_roles(user, tenant, _context),
    do: user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])

  @impl true
  def tenant_of(%{workspace_id: workspace_id}), do: workspace_id
  def tenant_of(_value), do: nil
end

defmodule Warden.RedteamV03.SubscriptionTest do
  # `Warden.Absinthe.Subscription.run_docset/3` skips the push for a subscriber whose
  # subscription root Warden denies. Every test asserts the secure behaviour: a failing
  # test is an open hole. Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.CompileHelpers

  alias Warden.Test.Pubsub
  alias Warden.Test.RedteamV2.Card

  @body """
    object :member_card do
      authorize tenant_role(:member)
      field :id, non_null(:integer)
    end

    query do
      field :ping, :string do
        authorize public()
        resolve fn _args, _resolution -> {:ok, "pong"} end
      end
    end

    subscription do
      field :member_cards, list_of(:member_card) do
        authorize public()
        config fn _args, _info -> {:ok, topic: "member_cards"} end
      end

      field :required_member_cards, list_of(non_null(:member_card)) do
        authorize public()
        config fn _args, _info -> {:ok, topic: "required_member_cards"} end
      end

      field :staff_card, :member_card do
        authorize role(:staff)
        config fn _args, _info -> {:ok, topic: "staff_card"} end

        resolve fn card, _args, resolution ->
          actor = Warden.Absinthe.actor(resolution)
          send(resolution.context.test_pid, {:publish_actor, actor})
          {:ok, card}
        end
      end
    end
  """

  # Abby is a member of t1 only; card 3 lives in t2.
  @abby %{id: "abby", memberships: %{"t1" => [:member]}}
  @kim %{id: "kim", memberships: %{"t2" => [:member]}}

  setup_all do
    schemas =
      for policy <- [:null_item, :filter, :fail_list], into: %{} do
        opts = "authorizer: Warden.RedteamV03.SubAuthz, list_policy: #{inspect(policy)}"
        {policy, compile_schema(@body, opts)}
      end

    %{schemas: schemas}
  end

  defp subscribe(schema, document, user, extra \\ %{}) do
    context = Map.merge(%{current_user: user, test_pid: self(), pubsub: Pubsub}, extra)
    {:ok, %{"subscribed" => topic}} = Absinthe.run(document, schema, context: context)
    :ok = Pubsub.subscribe(topic)
    topic
  end

  defp pushes(topic, collected \\ []) do
    receive do
      {:subscription_data, ^topic, data} -> pushes(topic, [data | collected])
    after
      200 -> Enum.reverse(collected)
    end
  end

  defp publish(value, topics), do: :ok = Absinthe.Subscription.publish(Pubsub, value, topics)

  # The design's own reason for the skip: "a null push still tells that the event
  # happened". A list root whose every item Warden denies is pushed as `[null]`, `[]` or
  # a nulled field with errors, which tells the same thing; only `:fail_list` skips.
  describe "a list root whose every item is denied" do
    test "null_item: nothing is pushed", %{schemas: schemas} do
      topic = subscribe(schemas.null_item, "subscription { memberCards { id } }", @abby)
      publish([Card.get(3)], member_cards: "member_cards")
      assert pushes(topic) == []
    end

    test "filter: nothing is pushed", %{schemas: schemas} do
      topic = subscribe(schemas.filter, "subscription { memberCards { id } }", @abby)
      publish([Card.get(3)], member_cards: "member_cards")
      assert pushes(topic) == []
    end

    test "fail_list: nothing is pushed", %{schemas: schemas} do
      topic = subscribe(schemas.fail_list, "subscription { memberCards { id } }", @abby)
      publish([Card.get(3)], member_cards: "member_cards")
      assert pushes(topic) == []
    end

    # Here Warden's denial nulls the root field itself (non-null items), which is the
    # documented trigger for the skip.
    test "non-null items: a root nulled by an item denial is not pushed", %{schemas: schemas} do
      document = "subscription { requiredMemberCards { id } }"
      topic = subscribe(schemas.null_item, document, @abby)
      allowed = subscribe(schemas.null_item, document, @kim)
      publish([Card.get(3)], required_member_cards: "required_member_cards")

      assert pushes(topic) == []
      assert [%{data: %{"requiredMemberCards" => [%{"id" => 3}]}}] = pushes(allowed)
    end
  end

  describe "a list root that is not fully denied is pushed" do
    test "an empty list from the resolver", %{schemas: schemas} do
      for policy <- [:null_item, :filter] do
        topic = subscribe(schemas[policy], "subscription { memberCards { id } }", @abby)
        publish([], member_cards: "member_cards")
        assert [%{data: %{"memberCards" => []}}] = pushes(topic)
      end
    end

    test "null_item: an allowed item, the denied one nulled", %{schemas: schemas} do
      topic = subscribe(schemas.null_item, "subscription { memberCards { id } }", @abby)
      publish([Card.get(1), Card.get(3)], member_cards: "member_cards")
      assert [%{data: %{"memberCards" => [%{"id" => 1}, nil]}}] = pushes(topic)
    end

    test "filter: an allowed item, the denied one filtered", %{schemas: schemas} do
      topic = subscribe(schemas.filter, "subscription { memberCards { id } }", @abby)
      publish([Card.get(3), Card.get(1)], member_cards: "member_cards")
      assert [%{data: %{"memberCards" => [%{"id" => 1}]}}] = pushes(topic)
    end
  end

  describe "a root field denied at publish time" do
    test "a role revoked after subscribe: no push, a new actor per publish", %{schemas: schemas} do
      {:ok, roles} = Agent.start_link(fn -> [:staff] end)
      member = Map.put(@kim, :roles, [])
      document = "subscription { staffCard { id } }"
      topic = subscribe(schemas.null_item, document, member, %{roles: roles})

      publish(Card.get(3), staff_card: "staff_card")
      assert [%{data: %{"staffCard" => %{"id" => 3}} = data} = push] = pushes(topic)
      assert Map.keys(push) == [:data]
      refute inspect(data) =~ "Warden"
      assert_received {:publish_actor, first_actor}

      Agent.update(roles, fn _roles -> [] end)
      publish(Card.get(3), staff_card: "staff_card")
      assert pushes(topic) == []
      refute_received {:publish_actor, _actor}

      Agent.update(roles, fn _roles -> [:staff] end)
      publish(Card.get(3), staff_card: "staff_card")
      assert [_push] = pushes(topic)
      assert_received {:publish_actor, second_actor}
      refute first_actor.instance == second_actor.instance
    end
  end
end
