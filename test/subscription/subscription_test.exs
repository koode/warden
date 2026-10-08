defmodule Warden.SubscriptionTest do
  # Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.Helpers

  alias Warden.Test.{Data, Pubsub}

  @schema Warden.Test.Schema

  defp subscribe(doc, user, extra \\ %{}) do
    context = Map.merge(%{pubsub: Pubsub, current_user: user, test_pid: self()}, extra)

    case Absinthe.run(doc, @schema, context: context) do
      {:ok, %{"subscribed" => topic}} ->
        :ok = Pubsub.subscribe(topic)
        {:ok, topic}

      {:ok, %{errors: errors}} ->
        {:error, errors}
    end
  end

  defp publish(value, topics) do
    :ok = Absinthe.Subscription.publish(Pubsub, value, topics)
  end

  defp receive_data(topic) do
    receive do
      {:subscription_data, ^topic, data} -> data
    after
      1000 -> flunk("no data published to #{topic}")
    end
  end

  defp secret, do: hd(Data.secrets())

  describe "subscribe time" do
    test "a denied subscription field refuses the subscription" do
      assert {:error, [error]} = subscribe("subscription { adminFeed }", viewer())
      assert error.message == "Forbidden"
      assert error.extensions == %{code: "FORBIDDEN"}
    end

    test "a denied argument refuses the subscription" do
      assert {:error, [_]} = subscribe("subscription { adminFeed(verbose: true) }", admin())
      assert {:ok, _} = subscribe("subscription { adminFeed(verbose: false) }", admin())
      assert {:ok, _} = subscribe("subscription { adminFeed }", admin())
    end

    test "an allowed subscription subscribes; no config means the field name is the topic" do
      assert {:ok, _} = subscribe("subscription { adminFeed }", admin())
      assert {:ok, topic} = subscribe("subscription { defaultConfig { id } }", viewer())
      publish(hd(Data.posts()), default_config: "default_config")
      assert %{data: %{"defaultConfig" => %{"id" => "p1"}}} = receive_data(topic)
    end
  end

  describe "publish time" do
    test "two subscribers with different roles on the same topic each get their own view" do
      {:ok, admin_topic} = subscribe("subscription { secretRotated { id code } }", admin())
      {:ok, viewer_topic} = subscribe("subscription { secretRotated { id code } }", viewer())
      assert admin_topic != viewer_topic

      publish(secret(), secret_rotated: "secrets")

      assert receive_data(admin_topic) == %{
               data: %{"secretRotated" => %{"id" => "s1", "code" => "ALPHA"}}
             }

      viewer_data = receive_data(viewer_topic)
      assert viewer_data.data == %{"secretRotated" => nil}
      assert [%{message: "Forbidden"}] = viewer_data.errors
    end

    test "a revoked role applies on the next publish" do
      {:ok, store} = Agent.start_link(fn -> [:admin] end)
      roles_fun = fn _user -> Agent.get(store, & &1) end

      {:ok, topic} =
        subscribe("subscription { secretRotated { code } }", admin(), %{roles_fun: roles_fun})

      publish(secret(), secret_rotated: "secrets")
      assert receive_data(topic).data == %{"secretRotated" => %{"code" => "ALPHA"}}

      Agent.update(store, fn _ -> [:viewer] end)
      publish(secret(), secret_rotated: "secrets")
      assert receive_data(topic).data == %{"secretRotated" => nil}

      Agent.update(store, fn _ -> [:admin] end)
      publish(secret(), secret_rotated: "secrets")
      assert receive_data(topic).data == %{"secretRotated" => %{"code" => "ALPHA"}}
    end

    test "a revoked field rule applies on the next publish" do
      {:ok, store} = Agent.start_link(fn -> [:admin] end)
      roles_fun = fn _user -> Agent.get(store, & &1) end
      {:ok, topic} = subscribe("subscription { adminFeed }", admin(), %{roles_fun: roles_fun})

      publish("hello", admin_feed: "admin")
      assert receive_data(topic).data == %{"adminFeed" => "hello"}

      Agent.update(store, fn _ -> [] end)
      publish("hello", admin_feed: "admin")
      data = receive_data(topic)
      assert data.data == %{"adminFeed" => nil}
      assert [%{path: ["adminFeed"]}] = data.errors
    end

    test "the publisher's identity is never used" do
      {:ok, topic} = subscribe("subscription { secretRotated { code } }", viewer())

      # An admin's mutation publishes; the subscriber documents resolve in the same
      # process while the admin's execution is live.
      result = run("mutation { rotateSecret }", admin(), context: %{pubsub: Pubsub})
      assert result.data == %{"rotateSecret" => true}

      data = receive_data(topic)
      assert data.data == %{"secretRotated" => nil}
      assert [%{message: "Forbidden"}] = data.errors
    end
  end

  describe "context_id" do
    test "subscribers with the same context_id but different access do not share a payload" do
      doc = "subscription { sharedUser { id email } }"
      {:ok, viewer_topic} = subscribe(doc, viewer())
      {:ok, nobody_topic} = subscribe(doc, nobody())
      {:ok, viewer2_topic} = subscribe(doc, viewer())

      assert viewer_topic != nobody_topic
      assert String.contains?(viewer_topic, "global:warden:")
      # Same access, same key: sharing is still possible, as Absinthe intends.
      assert viewer_topic == viewer2_topic

      publish(Data.user("u1"), shared_user: "users")

      viewer_data = receive_data(viewer_topic)
      nobody_data = receive_data(nobody_topic)

      assert viewer_data.data == %{"sharedUser" => %{"id" => "u1", "email" => nil}}
      assert nobody_data.data == %{"sharedUser" => nil}
    end

    test "a config returned as a map is fingerprinted too" do
      doc = "subscription { sharedUserMap { id email } }"
      {:ok, viewer_topic} = subscribe(doc, viewer())
      {:ok, nobody_topic} = subscribe(doc, nobody())
      assert viewer_topic != nobody_topic
      assert String.contains?(viewer_topic, "global:warden:")
    end

    test "subscribers with different subjects but the same roles get different keys" do
      doc = "subscription { sharedUser { id email } }"
      {:ok, bob} = subscribe(doc, Data.as(:viewer, "u2"))
      {:ok, alice} = subscribe(doc, Data.as(:viewer, "u1"))
      assert bob != alice

      publish(Data.user("u1"), shared_user: "users")
      # check(:self) lets Alice see her own email, Bob does not.
      assert receive_data(alice).data == %{
               "sharedUser" => %{"id" => "u1", "email" => "alice@example.com"}
             }

      assert receive_data(bob).data == %{"sharedUser" => %{"id" => "u1", "email" => nil}}
    end
  end
end
