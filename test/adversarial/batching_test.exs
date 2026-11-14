defmodule Warden.Adversarial.BatchingTest do
  @moduledoc """
  Attacks on batched decisions in GraphQL: cost that grows with denied items, a
  `BatchResolver` loop through cross-parent batching, and broken batch callbacks that
  could leave a value visible.
  """
  use ExUnit.Case, async: false

  import Warden.Test.V2.People

  alias Absinthe.Phase.Document.Result
  alias Absinthe.Pipeline
  alias Absinthe.Pipeline.BatchResolver

  @ratio_bound 24

  defmodule Schema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Absinthe, authorizer: Warden.Test.V2.Authz, batch_across_parents: true

    object :person do
      authorize check(:configured_many)
      field :name, :string
    end

    object :box do
      field :id, :integer

      field :owner, :person do
        resolve fn box, _args, _resolution -> {:ok, %{name: "owner #{box.id}"}} end
      end
    end

    query do
      field :people, list_of(:person) do
        arg :n, non_null(:integer)
        resolve fn %{n: n}, _resolution -> {:ok, Enum.map(1..n, &%{name: "p#{&1}"})} end
      end

      field :boxes, list_of(:box) do
        arg :n, non_null(:integer)
        resolve fn %{n: n}, _resolution -> {:ok, Enum.map(1..n, &%{id: &1})} end
      end
    end
  end

  defp run(doc, extra) do
    {:ok, result} = Absinthe.run(doc, Schema, context: context(abby(), extra))
    result
  end

  defp deny_all, do: %{many_result: fn checks -> Enum.map(checks, fn _check -> false end) end}

  defp time(doc) do
    run(doc, deny_all())

    1..5
    |> Enum.map(fn _attempt -> :timer.tc(fn -> run(doc, deny_all()) end) |> elem(0) end)
    |> Enum.min()
  end

  test "deciding a batched rule over every denied item grows about linearly" do
    for template <- ["{ people(n: N) { name } }", "{ boxes(n: N) { owner { name } } }"] do
      small = time(String.replace(template, "N", "1000"))
      large = time(String.replace(template, "N", "8000"))

      IO.puts(
        "[cost] #{template}: 1000 -> #{div(small, 1000)} ms, 8000 -> #{div(large, 1000)} ms"
      )

      assert large / max(small, 1) < @ratio_bound
    end
  end

  # BatchResolver shares the accumulator and the context between documents (a documented
  # limit of 0.1), so the documents here belong to one user.
  test "BatchResolver finishes with cross-parent batching and each document gets its result" do
    many_result = fn checks -> Enum.map(checks, &(&1.value.name != "owner 2")) end

    pipeline = fn user ->
      Schema
      |> Pipeline.for_document(context: context(user, %{many_result: many_result}))
      |> Pipeline.before(Absinthe.Phase.Document.Execution.Resolution)
    end

    blueprints =
      for count <- [3, 2] do
        {:ok, blueprint, _phases} =
          Pipeline.run("{ boxes(n: #{count}) { owner { name } } }", pipeline.(abby()))

        blueprint
      end

    task = Task.async(fn -> BatchResolver.run(blueprints, schema: Schema) end)

    assert {:ok, [first, second]} =
             Task.yield(task, 5_000) || Task.shutdown(task, :brutal_kill)

    owners = fn blueprint ->
      {:ok, blueprint} = Result.run(blueprint, [])
      blueprint.result.data["boxes"] |> Enum.map(& &1["owner"])
    end

    assert owners.(first) == [%{"name" => "owner 1"}, nil, %{"name" => "owner 3"}]
    assert owners.(second) == [%{"name" => "owner 1"}, nil]
  end

  test "a broken batch never leaves a value visible" do
    for many_result <- [
          fn checks -> Enum.map(tl(checks), fn _check -> true end) end,
          fn _checks -> raise "boom" end,
          fn checks -> Enum.map(checks, fn _check -> :ok end) end
        ] do
      for doc <- ["{ people(n: 3) { name } }", "{ boxes(n: 3) { owner { name } } }"] do
        outcome =
          try do
            run(doc, %{many_result: many_result})
          rescue
            Warden.PolicyError -> :raised
          end

        refute inspect(outcome) =~ ~r/"p\d"|owner \d/
      end
    end
  end
end
