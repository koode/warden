defmodule Warden.Adversarial.CostTest do
  @moduledoc """
  Denial-of-service guard: the cost of item errors and nested-list folds must grow about
  linearly with the number of denied items. Compares 1,000 against 8,000 items (8x the
  work); linear growth gives a ratio near 8, quadratic growth near 64. The bound is
  generous so machine noise does not fail it, but quadratic cost does.
  """
  use ExUnit.Case, async: false

  import Warden.Test.Helpers

  @ratio_bound 24

  defmodule Schema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Schema, authorizer: Warden.Test.Authz

    object :secret do
      authorize role(:admin)
      field :id, :id
    end

    object :cell do
      field :id, :id

      field :hidden, non_null(:string) do
        authorize role(:admin)
      end
    end

    query do
      field :big, list_of(:secret) do
        arg :n, non_null(:integer)
        resolve fn %{n: n}, _ -> {:ok, Enum.map(1..n, &%{id: "s#{&1}"})} end
      end

      field :grid, list_of(list_of(:cell)) do
        arg :n, non_null(:integer)
        resolve fn %{n: n}, _ -> {:ok, [Enum.map(1..n, &%{id: "c#{&1}", hidden: "h"})]} end
      end
    end
  end

  defp time(doc) do
    # Best of five, after a warm-up, in microseconds.
    run(doc, viewer(), schema: Schema)

    1..5
    |> Enum.map(fn _ -> :timer.tc(fn -> run(doc, viewer(), schema: Schema) end) |> elem(0) end)
    |> Enum.min()
  end

  defp ratio(template) do
    small = time(String.replace(template, "N", "1000"))
    large = time(String.replace(template, "N", "8000"))
    IO.puts("[cost] #{template}: 1000 -> #{div(small, 1000)} ms, 8000 -> #{div(large, 1000)} ms")
    large / max(small, 1)
  end

  test "item errors on every denied list item grow about linearly" do
    result = run("{ big(n: 3) { id } }", viewer(), schema: Schema)
    assert result.data == %{"big" => [nil, nil, nil]}
    assert length(result.errors) == 3

    assert ratio("{ big(n: N) { id } }") < @ratio_bound
  end

  test "nested-list folds grow about linearly" do
    result = run("{ grid(n: 3) { id hidden } }", viewer(), schema: Schema)
    assert result.data == %{"grid" => [[nil, nil, nil]]}

    assert ratio("{ grid(n: N) { id hidden } }") < @ratio_bound
  end

  test "no Warden marker reaches the client response or the result tree" do
    {:ok, bp, _} =
      Absinthe.Pipeline.run(
        "{ big(n: 2) { id } grid(n: 2) { id hidden } }",
        Absinthe.Pipeline.for_document(Schema, context: %{current_user: viewer()})
      )

    refute inspect(bp.execution.result) =~ "Warden =>"
    refute inspect(bp.result) =~ "Warden"
  end
end
