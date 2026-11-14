defmodule Warden.RedteamMythos.FeedSchema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.RedteamV2.Authz

  alias Warden.Test.RedteamV2.{Card, CardFields, Cards}

  object :card do
    authorize can(Cards, :read)
    redact_with CardFields
    field :id, non_null(:integer)
    field :note, :string
  end

  # A value-dependent rule that differs per subscriber: members of the card's workspace.
  object :member_card do
    authorize tenant_role(:member)
    field :id, non_null(:integer)
  end

  # Raises for a subscriber whose context asks for it, to prove one failing document does
  # not stop the others.
  def resolve_published(card, _args, %{context: context}) do
    if Map.get(context, :raise_on_publish), do: raise("publish failed"), else: {:ok, card}
  end

  query do
    field :card, :card do
      arg :id, non_null(:integer)
      resolve fn args, _resolution -> {:ok, Card.get(args.id)} end
    end
  end

  subscription do
    # Decided: the subscribe is refused for a card the subscriber may not read.
    field :card_changed, :card do
      arg :id, non_null(:integer)
      authorize can(Cards, :read, arg: [:id])
      config fn args, _info -> {:ok, topic: "card:#{args.id}"} end
      resolve fn card, _args, _resolution -> {:ok, card} end
    end

    field :card_published, :card do
      authorize public()
      config fn _args, _info -> {:ok, topic: "cards"} end
      resolve &__MODULE__.resolve_published/3
    end

    # Only the object rule of the payload decides; `public()` acknowledges that.
    field :member_card_changed, :member_card do
      authorize public()
      arg :id, non_null(:integer)
      config fn args, _info -> {:ok, topic: "member_card:#{args.id}"} end
    end
  end
end

defmodule Warden.RedteamMythos.PlainPubsub do
  @moduledoc false
  # A pubsub that does not delegate `run_docset/3` to Warden, so Absinthe's own publish
  # loop runs. Delivers through the registry of `Warden.Test.Pubsub`.
  @behaviour Absinthe.Subscription.Pubsub

  @impl true
  def node_name, do: to_string(node())

  @impl true
  def subscribe(topic), do: Warden.Test.Pubsub.subscribe(topic)

  @impl true
  def publish_mutation(_proxy_topic, _mutation_result, _subscribed_fields), do: :ok

  @impl true
  def publish_subscription(topic, data), do: Warden.Test.Pubsub.publish_subscription(topic, data)
end

defmodule Warden.RedteamMythos.AbsintheTest do
  # Red-team of the Absinthe layer. Every test asserts the secure behaviour, so a failing
  # test is an open hole. Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Warden.Test.CompileHelpers

  alias Warden.RedteamMythos.{FeedSchema, PlainPubsub}
  alias Warden.Test.Pubsub
  alias Warden.Test.RedteamV2.{Card, People}

  @interface_schema """
    alias Warden.Test.RedteamV2.{Card, Cards}

    interface :entry do
      authorize can(Cards, :read)
      field :id, non_null(:integer)
      resolve_type fn _value, _resolution -> :card end
    end

    object :card do
      interface :entry
      field :id, non_null(:integer)
      field :note, :string
    end

    query do
      field :cards, list_of(:card) do
        resolve fn _args, _resolution -> {:ok, Card.all()} end
      end
    end
  """

  @own_rule_schema """
    alias Warden.Test.RedteamV2.{Card, Cards}

    object :card do
      authorize can(Cards, :read)
      field :id, non_null(:integer)
      field :note, :string
    end

    query do
      field :cards, list_of(:card) do
        resolve fn _args, _resolution -> {:ok, Card.all()} end
      end
    end
  """

  @authorizer "authorizer: Warden.Test.RedteamV2.Authz"

  defp compile_outcome(body) do
    {:ok, compile_schema(body, @authorizer)}
  rescue
    error in CompileError -> {:refused, Exception.message(error)}
  end

  defp subscribe(document, user, schema \\ FeedSchema, pubsub \\ Pubsub) do
    context = People.context(user, %{pubsub: pubsub})

    case Absinthe.run(document, schema, context: context) do
      {:ok, %{"subscribed" => topic}} ->
        :ok = Pubsub.subscribe(topic)
        {:ok, topic}

      {:ok, %{errors: errors}} ->
        {:error, errors}
    end
  end

  defp pushes(topic, collected) do
    receive do
      {:subscription_data, ^topic, data} -> pushes(topic, [data | collected])
    after
      200 -> Enum.reverse(collected)
    end
  end

  describe "HOLE: redact_with is only required when the can/2 rule is the type's own" do
    test "baseline: a type whose own rule is can/2 must declare redact_with" do
      assert {:refused, message} = compile_outcome(@own_rule_schema)
      assert message =~ "redact_with"
    end

    test "a type that gets its can/2 rule from an interface must declare it too" do
      case compile_outcome(@interface_schema) do
        {:refused, message} ->
          assert message =~ "redact_with"

        {:ok, schema} ->
          result = People.run(schema, "{ cards { id note } }", People.abby())
          notes = for %{"note" => note} <- result.data["cards"] || [], do: note

          flunk("""
          the schema compiled without `redact_with`, and a reader who is not staff got the \
          notes that the field policy redacts: #{inspect(notes)}\
          """)
      end
    end
  end

  # Changed to match the decision: an unguarded subscription is a compile-time warning,
  # `can(Policy, :read, arg: [:id])` on the field refuses the subscribe, and a payload
  # whose root object is denied at publish time is not pushed at all.
  describe "HOLE: a subscriber is pushed an event for a payload it may not see" do
    test "a subscription guarded only by a value-dependent object rule pushes nothing for a hidden card" do
      unguarded = """
        alias Warden.Test.RedteamV2.{CardFields, Cards}

        object :card do
          authorize can(Cards, :read)
          redact_with CardFields
          field :id, non_null(:integer)
          field :note, :string
        end

        query do
          field :ok, :string
        end

        subscription do
          field :card_changed, :card do
            arg :id, non_null(:integer)
            config fn args, _info -> {:ok, topic: "card:\#{args.id}"} end
          end
        end
      """

      warnings =
        ExUnit.CaptureIO.capture_io(:stderr, fn -> send(self(), compile_outcome(unguarded)) end)

      assert_received {:ok, schema}
      assert warnings =~ ~s|subscription "card_changed"|
      assert warnings =~ "can(Policy, :read, arg: [:id])"

      document = "subscription { cardChanged(id: 2) { id } }"
      {:ok, topic} = subscribe(document, People.abby(), schema)
      :ok = Absinthe.Subscription.publish(Pubsub, Card.get(2), card_changed: "card:2")
      assert pushes(topic, []) == []

      {:ok, visible_topic} =
        subscribe("subscription { cardChanged(id: 1) { id } }", People.abby(), schema)

      :ok = Absinthe.Subscription.publish(Pubsub, Card.get(1), card_changed: "card:1")
      assert [%{data: %{"cardChanged" => %{"id" => 1}}}] = pushes(visible_topic, [])

      guarded =
        String.replace(
          unguarded,
          "arg :id, non_null(:integer)\n",
          "arg :id, non_null(:integer)\n      authorize can(Cards, :read, arg: [:id])\n"
        )

      refute ExUnit.CaptureIO.capture_io(:stderr, fn -> compile_outcome(guarded) end) =~
               "cardChanged"
    end

    test "can(..., arg: [:id]) refuses the subscribe for a hidden card" do
      hidden = Card.get(2)
      refute hidden.visible

      result = People.run(FeedSchema, "{ card(id: 2) { id } }", People.abby())
      assert result.data == %{"card" => nil}

      assert {:error, _errors} =
               subscribe("subscription { cardChanged(id: 2) { id note } }", People.abby())
    end
  end

  describe "held: subscriptions over a redacted type" do
    test "a visible card is pushed with its note redacted for a reader who is not staff" do
      {:ok, topic} = subscribe("subscription { cardChanged(id: 1) { id note } }", People.abby())
      :ok = Absinthe.Subscription.publish(Pubsub, Card.get(1), card_changed: "card:1")

      assert [%{data: %{"cardChanged" => %{"id" => 1, "note" => "[hidden]"}}}] = pushes(topic, [])
    end

    test "staff and a reader subscribed to one topic each get their own payload" do
      document = "subscription { cardChanged(id: 1) { note } }"
      {:ok, reader_topic} = subscribe(document, People.abby())
      {:ok, staff_topic} = subscribe(document, People.staff())
      assert reader_topic != staff_topic

      :ok = Absinthe.Subscription.publish(Pubsub, Card.get(1), card_changed: "card:1")

      assert [%{data: %{"cardChanged" => %{"note" => "[hidden]"}}}] = pushes(reader_topic, [])
      assert [%{data: %{"cardChanged" => %{"note" => "note 1"}}}] = pushes(staff_topic, [])
    end
  end

  describe "publish-time denial of the subscription root" do
    @document "subscription { memberCardChanged(id: 3) { id } }"

    test "two subscribers on one topic: only the allowed one receives" do
      member = %{id: "sam", memberships: %{"t2" => [:member]}}
      {:ok, member_topic} = subscribe(@document, member)
      {:ok, outsider_topic} = subscribe(@document, People.abby())

      :ok =
        Absinthe.Subscription.publish(Pubsub, Card.get(3), member_card_changed: "member_card:3")

      assert [%{data: %{"memberCardChanged" => %{"id" => 3}}}] = pushes(member_topic, [])
      assert pushes(outsider_topic, []) == []
    end

    test "a pubsub that does not delegate run_docset/3 keeps pushing null, and is warned about once" do
      start_supervised!({Absinthe.Subscription, PlainPubsub})
      {:ok, topic} = subscribe(@document, People.abby(), FeedSchema, PlainPubsub)

      first =
        capture_log(fn ->
          :ok =
            Absinthe.Subscription.publish(PlainPubsub, Card.get(3),
              member_card_changed: "member_card:3"
            )
        end)

      second =
        capture_log(fn ->
          :ok =
            Absinthe.Subscription.publish(PlainPubsub, Card.get(3),
              member_card_changed: "member_card:3"
            )
        end)

      assert [%{data: %{"memberCardChanged" => nil}}, %{data: %{"memberCardChanged" => nil}}] =
               pushes(topic, [])

      assert first =~ "run_docset"
      assert first =~ inspect(PlainPubsub)
      refute second =~ "run_docset"
    end

    test "a document that raises is logged and the other subscribers are still pushed" do
      document = "subscription { cardPublished { id } }"
      {:ok, topic} = subscribe(document, People.abby())
      context = People.context(People.abby(), %{pubsub: Pubsub, raise_on_publish: true})

      {:ok, %{"subscribed" => failing_topic}} =
        Absinthe.run(document, FeedSchema, context: context)

      :ok = Pubsub.subscribe(failing_topic)

      log =
        capture_log(fn ->
          :ok = Absinthe.Subscription.publish(Pubsub, Card.get(1), card_published: "cards")
        end)

      assert [%{data: %{"cardPublished" => %{"id" => 1}}}] = pushes(topic, [])
      assert pushes(failing_topic, []) == []
      assert log =~ "publish failed"
    end

    test "the publish loop mirrors the Absinthe release it was compared against" do
      # `Warden.Absinthe.Subscription.run_docset/3` copies Absinthe's own loop. A new
      # Absinthe release fails this test until the two loops are compared again.
      version = :absinthe |> Application.spec(:vsn) |> to_string()
      assert Version.match?(version, "~> 1.12.0")
    end
  end
end
