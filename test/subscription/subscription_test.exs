defmodule Warden.SubscriptionTest do
  # Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.Helpers

  alias Warden.Test.{Data, Pubsub}

  @schema Warden.Test.Schema

  defmodule OptIn.Authz do
    @moduledoc false
    use Warden.Authorizer, roles: [:member]

    def subject(ctx), do: ctx[:current_user]
    def roles(user, _), do: user.roles

    # The key covers the org from the context; nil opts out.
    def actor_key(_actor, %{org: nil}), do: nil
    def actor_key(actor, ctx), do: Warden.Authorizer.default_actor_key(actor) <> ":" <> ctx.org
  end

  defmodule OptIn.Schema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Schema, authorizer: Warden.SubscriptionTest.OptIn.Authz

    query do
      field :ok, :string
    end

    object :item do
      field :id, :id
    end

    subscription do
      field :feed, :item do
        config fn _, _ -> {:ok, topic: "feed", context_id: "global"} end
        resolve fn root, _, _ -> {:ok, root} end
      end
    end
  end

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
      # User: viewer or self (value-dependent, so both may subscribe).
      {:ok, admin_topic} = subscribe("subscription { sharedUser { id email } }", admin())
      {:ok, nobody_topic} = subscribe("subscription { sharedUser { id email } }", nobody())
      assert admin_topic != nobody_topic

      publish(Data.user("u2"), shared_user: "users")

      assert receive_data(admin_topic) == %{
               data: %{"sharedUser" => %{"id" => "u2", "email" => "bob@example.com"}}
             }

      nobody_data = receive_data(nobody_topic)
      assert nobody_data.data == %{"sharedUser" => nil}
      assert [%{message: "Forbidden"}] = nobody_data.errors
    end

    test "a return type whose value-independent rule denies refuses the subscription" do
      # Secret requires admin, with no check: a viewer could never see an event.
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { secretRotated { id code } }", viewer())

      assert {:ok, _} = subscribe("subscription { secretRotated { id code } }", admin())
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
      {:ok, topic} = subscribe("subscription { sharedUser { id email } }", nobody())

      # An admin's mutation publishes; the subscriber documents resolve in the same
      # process while the admin's execution is live.
      result = run("mutation { rotateSecret }", admin(), context: %{pubsub: Pubsub})
      assert result.data == %{"rotateSecret" => true}

      data = receive_data(topic)
      assert data.data == %{"sharedUser" => nil}
      assert [%{message: "Forbidden"}] = data.errors
    end
  end

  describe "context_id" do
    test "sharing is off by default: a user context_id is removed" do
      doc = "subscription { sharedUser { id email } }"
      {:ok, viewer_topic} = subscribe(doc, viewer())
      {:ok, nobody_topic} = subscribe(doc, nobody())
      {:ok, viewer2_topic} = subscribe(doc, viewer())

      assert Enum.uniq([viewer_topic, nobody_topic, viewer2_topic]) |> length() == 3
      refute String.contains?(viewer_topic, "global")

      publish(Data.user("u1"), shared_user: "users")

      assert receive_data(viewer_topic).data == %{"sharedUser" => %{"id" => "u1", "email" => nil}}

      assert receive_data(viewer2_topic).data == %{
               "sharedUser" => %{"id" => "u1", "email" => nil}
             }

      assert receive_data(nobody_topic).data == %{"sharedUser" => nil}
    end

    test "a config returned as a map loses its context_id too" do
      doc = "subscription { sharedUserMap { id email } }"
      {:ok, a} = subscribe(doc, viewer())
      {:ok, b} = subscribe(doc, viewer())
      assert a != b
      refute String.contains?(a, "global")
    end

    test "opt-in: actor_key/2 lets subscriptions with equal keys share" do
      doc = "subscription { feed { id } }"
      ctx = %{pubsub: Pubsub, test_pid: self()}

      sub = fn user, org ->
        {:ok, %{"subscribed" => topic}} =
          Absinthe.run(doc, OptIn.Schema,
            context: Map.merge(ctx, %{current_user: user, org: org})
          )

        :ok = Pubsub.subscribe(topic)
        topic
      end

      a = sub.(%{id: "x", roles: [:member]}, "acme")
      b = sub.(%{id: "x", roles: [:member]}, "acme")
      c = sub.(%{id: "x", roles: [:member]}, "globex")
      d = sub.(%{id: "x", roles: []}, "acme")

      assert a == b
      assert String.contains?(a, "global:warden:")
      assert a != c
      assert a != d

      e = sub.(%{id: "x", roles: [:member]}, nil)
      refute String.contains?(e, "global")
    end
  end
end
