defmodule Warden.Adversarial.FieldsCostTest do
  @moduledoc """
  Denial-of-service guard for redaction: the cost of `Warden.redact/3` (shallow and deep)
  and of `redact_with` over a GraphQL list must grow about linearly with the number of
  structs. Compares 2,000 against 16,000 (8x the work); linear growth gives a ratio near
  8, quadratic growth near 64. Each timed run starts after a garbage collection, so a
  collection inside the short baseline run does not skew the ratio.
  """
  use ExUnit.Case, async: false

  alias Warden.Test.Fields.{Authz, Comment, Issue}

  @ratio_bound 24
  @ratio_attempts 3
  @trashed ~U[2026-11-01 10:00:00Z]

  defp user, do: %{id: "sam", memberships: %{"t1" => [:member]}}

  defp comments(count) do
    for id <- 1..count do
      trashed_at = if rem(id, 2) == 0, do: @trashed, else: nil
      %Comment{id: id, workspace_id: "t1", author_id: "abby", body: "b", trashed_at: trashed_at}
    end
  end

  defp best_time(fun) do
    fun.()

    1..5
    |> Enum.map(fn _attempt ->
      :erlang.garbage_collect()
      fun |> :timer.tc() |> elem(0)
    end)
    |> Enum.min()
  end

  defp ratio(make_fun) do
    Enum.reduce_while(1..@ratio_attempts, nil, fn _attempt, lowest ->
      small = best_time(make_fun.(2_000))
      large = best_time(make_fun.(16_000))
      measured = large / max(small, 1)
      lowest = if lowest == nil, do: measured, else: min(lowest, measured)
      if lowest < @ratio_bound, do: {:halt, lowest}, else: {:cont, lowest}
    end)
  end

  test "redacting a list grows linearly" do
    actor = Warden.actor(%{current_user: user()}, authorizer: Authz)

    measured =
      ratio(fn count ->
        values = comments(count)
        fn -> Warden.redact(actor, values) end
      end)

    assert measured < @ratio_bound
  end

  test "deep redaction grows linearly" do
    actor = Warden.actor(%{current_user: user()}, authorizer: Authz)

    measured =
      ratio(fn count ->
        issues =
          for {chunk, id} <- count |> comments() |> Enum.chunk_every(10) |> Enum.with_index() do
            %Issue{id: id, tenant_id: "t1", title: "T", comments: chunk}
          end

        fn -> Warden.redact(actor, %{issues: issues}, deep: true) end
      end)

    assert measured < @ratio_bound
  end

  test "redact_with over a GraphQL list grows linearly" do
    measured =
      ratio(fn count ->
        context = %{current_user: user(), comments: comments(count)}

        fn ->
          {:ok, _result} =
            Absinthe.run("{ comments { body authorId } }", Warden.Test.Fields.Schema,
              context: context
            )
        end
      end)

    assert measured < @ratio_bound
  end
end
