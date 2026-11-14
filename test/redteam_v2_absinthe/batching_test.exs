defmodule Warden.RedteamV2Absinthe.BatchingTest do
  # Attacks on batched checks over lists and `batch_across_parents: true`. Tests marked
  # HOLE fail while the hole exists; the others document defended attacks.
  use ExUnit.Case, async: true

  import Warden.Test.RedteamV2.People

  alias Warden.Test.RedteamV2.{AcrossSchema, Card, Schema, Ticket}

  defp holder(id, card, ticket), do: %{id: id, card: card, ticket: ticket}

  def forward_batch_start(_event, _measurements, metadata, test_pid) do
    rendered = inspect(metadata, limit: :infinity)
    send(test_pid, {:batch_start, rendered})
  end

  # Cross-parent batching hands Absinthe's `Batch` middleware the deferred
  # `%Warden.Check{}`s as batch data, which Absinthe puts in the metadata of its
  # `[:absinthe, :middleware, :batch, :start]` event. Inspecting that metadata (what a
  # logging handler does) shows neither the subject nor the unredacted value.
  test "cross-parent batching does not publish subjects or guarded values in telemetry" do
    handler = "redteam-v2-batch-#{System.unique_integer([:positive])}"
    test_pid = self()

    :ok =
      :telemetry.attach(
        handler,
        [:absinthe, :middleware, :batch, :start],
        &__MODULE__.forward_batch_start/4,
        test_pid
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    card = %Card{id: 1, workspace_id: "t1", note: "unredacted secret note"}
    holders = [holder(1, card, nil), holder(2, card, nil)]

    result = run(AcrossSchema, "{ holders { card { note } } }", abby(), %{holders: holders})

    assert [%{"card" => %{"note" => "[hidden]"}}, _second] = result.data["holders"]
    assert_received {:batch_start, metadata}
    refute metadata =~ "unredacted secret note"
    refute metadata =~ "abby"
  end

  # Changed to match the decided semantics: the check sleeps past its own `timeout:`
  # (6 s), so it denies with :unavailable; a check that answers within its timeout is
  # decided by its answer.
  # HOLE (low): a check's `timeout:` promises that on timeout every value denies with
  # reason `:unavailable`. Under `batch_across_parents: true` the check runs inside
  # Absinthe's batch task, which Absinthe gives 5 s by default; a longer `timeout:` makes
  # the whole document exit instead of denying.
  @tag timeout: 30_000
  test "a cross-parent check slower than Absinthe's batch timeout denies instead of exiting" do
    holders = [holder(1, nil, %Ticket{id: 1}), holder(2, nil, %Ticket{id: 2})]
    test_pid = self()

    task =
      Task.async(fn ->
        Process.flag(:trap_exit, true)

        try do
          {:ok,
           run(AcrossSchema, "{ holders { slowTicket { id } } }", abby(), %{
             holders: holders,
             sleep: 6_500,
             test_pid: test_pid
           })}
        catch
          :exit, reason -> {:exited, reason}
        end
      end)

    outcome = Task.await(task, 20_000)

    assert {:ok, result} = outcome
    assert result.data["holders"] == [%{"slowTicket" => nil}, %{"slowTicket" => nil}]
  end

  # HOLE (medium, cost): `decide_across_parents/2` groups the deferred checks by
  # `{actor, context}`, hashing the whole context once per check. A context that grows
  # with the result (a Dataloader whose cache holds every loaded row, or the rows
  # themselves as here) makes one level cost items x context size: 1,000 items took
  # 0.5 s, 4,000 took 5 s, and 8,000 exceed Absinthe's 5 s batch timeout, so the whole
  # document exits. The same document without the rows in the context takes 0.1 s.
  test "8,000 cross-parent checks with every other one denied stay linear and fold" do
    holders =
      for index <- 1..8_000 do
        holder(index, nil, %Ticket{id: index, visible: rem(index, 2) == 0})
      end

    document = "{ holders { id requiredTicket { id } } }"

    {micros, outcome} =
      :timer.tc(fn ->
        try do
          {:ok, run(AcrossSchema, document, abby(), %{holders: holders})}
        catch
          :exit, reason -> {:exited, reason}
        end
      end)

    assert {:ok, result} = outcome, "the document exited after #{div(micros, 1000)} ms"
    items = result.data["holders"]
    assert Enum.count(items) == 8_000
    assert Enum.at(items, 0) == nil
    assert Enum.at(items, 1) == %{"id" => 2, "requiredTicket" => %{"id" => 2}}
    assert micros < 8_000_000, "took #{div(micros, 1000)} ms"
    assert_received {:check_many, :live, 8_000}
  end

  test "a policy answer of the wrong shape over a list fails closed" do
    filtering = fn values -> Enum.filter(values, & &1.visible) end

    assert_raise Warden.PolicyError, fn ->
      run(Schema, "{ cards { id note } }", abby(), %{policy_many: filtering})
    end
  end

  # HOLE (low): the `Warden.PolicyError` for a wrong-shaped policy answer inspects the
  # answer. A plausible bug (`Enum.filter/2` instead of `Enum.map/2` in `allowed_many/4`)
  # returns the values themselves, so the guarded values land in the exception message
  # and from there in logs and error trackers. The field-policy errors avoid this ("names
  # the policy and the struct module, never the value").
  test "a wrong-shaped policy answer does not put guarded values in the error message" do
    filtering = fn values -> Enum.filter(values, & &1.visible) end

    error =
      assert_raise Warden.PolicyError, fn ->
        run(Schema, "{ cards { id } }", abby(), %{policy_many: filtering})
      end

    refute Exception.message(error) =~ "note 1"
  end

  test "a raising batched check under cross-parent batching never leaves a value visible" do
    raising = fn _values -> raise "policy store down" end
    card = %Card{id: 1, workspace_id: "t1", note: "x"}

    caught =
      try do
        run(AcrossSchema, "{ holders { card { id } } }", abby(), %{
          holders: [holder(1, card, nil)],
          policy_many: raising
        })
      rescue
        error -> {:raised, error}
      end

    assert {:raised, %Warden.PolicyError{}} = caught
  end
end
