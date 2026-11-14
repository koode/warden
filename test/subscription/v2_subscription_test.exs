defmodule Warden.V2SubscriptionTest do
  # Not async: subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.V2.People

  alias Warden.Test.Pubsub
  alias Warden.Test.V2.Doc

  @schema Warden.Test.V2.Schema
  @document ~s|subscription { docUpdated(workspaceId: "t1") { id body } }|

  defp subscribe(user, extra) do
    context = Map.merge(context(user, extra), %{pubsub: Pubsub})

    case Absinthe.run(@document, @schema, context: context) do
      {:ok, %{"subscribed" => topic}} ->
        :ok = Pubsub.subscribe(topic)
        {:ok, topic}

      {:ok, %{errors: errors}} ->
        {:error, errors}
    end
  end

  defp publish(doc), do: :ok = Absinthe.Subscription.publish(Pubsub, doc, doc_updated: "docs:t1")

  defp receive_data(topic) do
    receive do
      {:subscription_data, ^topic, data} -> data
    after
      1000 -> flunk("no data published to #{topic}")
    end
  end

  defp tenant_role_reads do
    receive do
      {:tenant_roles, user_id, tenant} -> [{user_id, tenant} | tenant_role_reads()]
    after
      0 -> []
    end
  end

  test "a tenant the subscriber is not in refuses the subscription" do
    assert {:error, [%{message: "Forbidden"}]} =
             Absinthe.run(~s|subscription { docUpdated(workspaceId: "t3") { id } }|, @schema,
               context: Map.put(context(abby()), :pubsub, Pubsub)
             )
             |> then(fn {:ok, %{errors: errors}} -> {:error, errors} end)
  end

  test "every publish rebuilds the actor: tenant roles are read again and the policy decides again" do
    # Sam is a member of t1 on subscribe; his membership is read from a live table on
    # every publish, so a revocation applies to the next event.
    table = :ets.new(:memberships, [:public])
    :ets.insert(table, {"sam", [:member]})

    roles = fn user, _tenant ->
      [{_user, roles}] = :ets.lookup(table, user.id)
      roles
    end

    {:ok, topic} = subscribe(sam(), %{tenant_roles_fun: roles})
    assert tenant_role_reads() == [{"sam", "t1"}]

    publish(Doc.get(2))
    assert receive_data(topic) == %{data: %{"docUpdated" => %{"id" => 2, "body" => "doc body"}}}

    publish(Doc.get(1))
    assert receive_data(topic) == %{data: %{"docUpdated" => nil}}
  end

  test "the tenant-role cache does not survive into the next publish" do
    {:ok, topic} = subscribe(abby(), %{})
    tenant_role_reads()

    for _publish <- 1..3 do
      publish(Doc.get(1))
      assert %{data: %{"docUpdated" => %{"id" => 1}}} = receive_data(topic)
    end

    assert tenant_role_reads() == [{"abby", "t1"}, {"abby", "t1"}, {"abby", "t1"}]
  end
end
