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
  end
end

defmodule Warden.RedteamMythos.AbsintheTest do
  # Red-team of the Absinthe layer. Every test asserts the secure behaviour, so a failing
  # test is an open hole. Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.CompileHelpers

  alias Warden.RedteamMythos.FeedSchema
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

  defp subscribe(document, user) do
    context = People.context(user, %{pubsub: Pubsub})

    case Absinthe.run(document, FeedSchema, context: context) do
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
  # and `can(Policy, :read, arg: [:id])` on the field refuses the subscribe.
  describe "HOLE: a subscriber is pushed an event for a payload it may not see" do
    test "a subscription guarded only by a value-dependent object rule warns at compile time" do
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

      warnings = ExUnit.CaptureIO.capture_io(:stderr, fn -> compile_outcome(unguarded) end)
      assert warnings =~ ~s|subscription "card_changed"|
      assert warnings =~ "can(Policy, :read, arg: [:id])"

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
end
