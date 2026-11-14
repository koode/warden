defmodule Warden.FieldsSubscriptionTest do
  # Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.Fields.People

  alias Warden.Test.Fields.Comment
  alias Warden.Test.Pubsub

  @schema Warden.Test.Fields.Schema
  @document "subscription { commentUpdated { id body authorId } }"

  defp subscribe(user, extra) do
    context = Map.merge(context(user, extra), %{pubsub: Pubsub})
    {:ok, %{"subscribed" => topic}} = Absinthe.run(@document, @schema, context: context)
    :ok = Pubsub.subscribe(topic)
    topic
  end

  defp publish(comment),
    do: :ok = Absinthe.Subscription.publish(Pubsub, comment, comment_updated: "fields:comments")

  defp receive_data(topic) do
    receive do
      {:subscription_data, ^topic, data} -> data
    after
      1000 -> flunk("no data published to #{topic}")
    end
  end

  test "redaction runs again on every publish: a revoked role redacts the next event" do
    table = :ets.new(:memberships, [:public])
    :ets.insert(table, {"sam", [:member]})

    roles = fn user, _tenant ->
      [{_user, roles}] = :ets.lookup(table, user.id)
      roles
    end

    topic = subscribe(sam(), %{tenant_roles_fun: roles})
    comment = %Comment{id: 1, workspace_id: "t1", author_id: "abby", body: "hello"}

    publish(comment)

    assert receive_data(topic) == %{
             data: %{"commentUpdated" => %{"id" => "1", "body" => "hello", "authorId" => "abby"}}
           }

    :ets.insert(table, {"sam", [:guest]})
    publish(comment)

    assert receive_data(topic) == %{
             data: %{"commentUpdated" => %{"id" => "1", "body" => "hello", "authorId" => nil}}
           }

    publish(%{comment | trashed_at: ~U[2026-11-01 10:00:00Z]})

    assert receive_data(topic) == %{
             data: %{"commentUpdated" => %{"id" => "1", "body" => "", "authorId" => nil}}
           }
  end

  test "two subscribers on one topic each get their own redaction" do
    member_topic = subscribe(sam(), %{})
    guest_topic = subscribe(olivia(), %{})
    publish(%Comment{id: 2, workspace_id: "t1", author_id: "abby", body: "hi"})

    assert %{data: %{"commentUpdated" => %{"authorId" => "abby"}}} = receive_data(member_topic)
    assert %{data: %{"commentUpdated" => %{"authorId" => nil}}} = receive_data(guest_topic)
  end
end
