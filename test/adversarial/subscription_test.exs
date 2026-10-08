defmodule Warden.Adversarial.SubscriptionTest do
  @moduledoc """
  Attempts to read another identity's data through subscriptions.
  """
  use ExUnit.Case, async: false

  import Warden.Test.Helpers

  alias Warden.Test.{Data, Pubsub}

  defp subscribe(doc, user) do
    {:ok, %{"subscribed" => topic}} =
      Absinthe.run(doc, Warden.Test.Schema, context: %{pubsub: Pubsub, current_user: user})

    :ok = Pubsub.subscribe(topic)
    topic
  end

  defp receive_data(topic) do
    receive do
      {:subscription_data, ^topic, data} -> data
    after
      1000 -> flunk("no data")
    end
  end

  test "two subscribers with different roles on one topic" do
    admin_topic = subscribe("subscription { secretRotated { code } }", admin())
    viewer_topic = subscribe("subscription { secretRotated { code } }", viewer())

    :ok = Absinthe.Subscription.publish(Pubsub, hd(Data.secrets()), secret_rotated: "secrets")

    assert receive_data(admin_topic).data == %{"secretRotated" => %{"code" => "ALPHA"}}
    assert receive_data(viewer_topic).data == %{"secretRotated" => nil}
  end

  test "context_id shared between a privileged and an unprivileged subscriber" do
    doc = "subscription { sharedUser { email } }"
    alice = subscribe(doc, Data.as(:viewer, "u1"))
    bob = subscribe(doc, Data.as(:viewer, "u2"))

    :ok = Absinthe.Subscription.publish(Pubsub, Data.user("u1"), shared_user: "users")

    assert receive_data(alice).data == %{"sharedUser" => %{"email" => "alice@example.com"}}
    assert receive_data(bob).data == %{"sharedUser" => %{"email" => nil}}
  end

  test "subscribing to a denied subscription field" do
    assert {:ok, %{errors: [%{message: "Forbidden"}]}} =
             Absinthe.run("subscription { adminFeed }", Warden.Test.Schema,
               context: %{pubsub: Pubsub, current_user: viewer()}
             )
  end

  test "subscribing with a restricted argument hidden in a variable" do
    assert {:ok, %{errors: [%{message: "Forbidden"}]}} =
             Absinthe.run(
               "subscription($v: Boolean) { adminFeed(verbose: $v) }",
               Warden.Test.Schema,
               context: %{pubsub: Pubsub, current_user: admin()},
               variables: %{"v" => true}
             )
  end

  test "denied publishing mutation does not publish" do
    topic = subscribe("subscription { secretRotated { code } }", admin())

    {:ok, result} =
      Absinthe.run("mutation { publishRotate }", Warden.Test.Adversarial.Schema,
        context: %{pubsub: Pubsub, current_user: viewer()}
      )

    assert result.data == %{"publishRotate" => nil}
    refute_receive {:subscription_data, ^topic, _}, 100
  end
end
