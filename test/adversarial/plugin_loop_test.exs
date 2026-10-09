defmodule Warden.Adversarial.PluginLoopTest do
  @moduledoc """
  `Absinthe.Pipeline.BatchResolver` keeps resolving while any plugin returns phases.
  No Warden plugin path may keep returning phases.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  defmodule Schema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Absinthe, authorizer: Warden.Test.Authz

    def plugins, do: [Absinthe.Middleware.Async | Absinthe.Plugin.defaults()]

    object :secret do
      authorize role(:admin)
      field :id, :id
    end

    # Denied list items record item errors; the denied non-null `locked` then folds the
    # box away, so those errors have nowhere to attach.
    object :box do
      field :secrets, list_of(:secret)

      field :async_secrets, list_of(:secret) do
        resolve fn box, _, _ ->
          Absinthe.Resolution.Helpers.async(fn -> {:ok, box.secrets} end)
        end
      end

      field :locked, non_null(:string) do
        authorize role(:admin)
      end
    end

    object :grid do
      field :rows, list_of(list_of(:cell))
    end

    object :cell do
      field :id, :id

      field :hidden, non_null(:string) do
        authorize role(:admin)
      end
    end

    query do
      field :box, :box do
        resolve fn _, _ -> {:ok, %{secrets: [%{id: "s1"}, %{id: "s2"}], locked: "x"}} end
      end

      field :grid, :grid do
        resolve fn _, _ ->
          {:ok, %{rows: [[%{id: "c1", hidden: "h"}], [%{id: "c2", hidden: "h"}]]}}
        end
      end
    end
  end

  defp batch(docs, user) do
    ctx = %{current_user: user, test_pid: self()}

    pipeline =
      Schema
      |> Absinthe.Pipeline.for_document(context: ctx)
      |> Absinthe.Pipeline.before(Absinthe.Phase.Document.Execution.Resolution)

    bps =
      for doc <- docs do
        {:ok, bp, _} = Absinthe.Pipeline.run(doc, pipeline)
        bp
      end

    task = Task.async(fn -> Absinthe.Pipeline.BatchResolver.run(bps, schema: Schema) end)
    Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill)
  end

  test "batch mode finishes when item errors cannot attach (parent folded away)" do
    assert {:ok, [_]} = batch(["{ box { secrets { id } locked } }"], viewer())
  end

  test "batch mode finishes with async fields and folds two list levels deep" do
    docs = [
      "{ box { asyncSecrets { id } locked } }",
      "{ grid { rows { id hidden } } }",
      "{ box { secrets { id } } }"
    ]

    assert {:ok, [_, _, _]} = batch(docs, viewer())
  end

  test "the plugin asks for its phase at most once, then never again" do
    exec = %Absinthe.Blueprint.Execution{acc: %{Warden => %{pending: true}}}

    # Another plugin wants a pass: Warden waits.
    assert Warden.Absinthe.Plugin.pipeline([Absinthe.Phase.Document.Execution.Resolution], exec) ==
             [Absinthe.Phase.Document.Execution.Resolution]

    assert Warden.Absinthe.Plugin.pipeline([], exec) == [Warden.Absinthe.Phase.ItemErrors]

    bp = %Absinthe.Blueprint{
      execution: %{exec | result: %Absinthe.Blueprint.Result.Leaf{emitter: nil, value: nil}}
    }

    {:ok, bp} = Warden.Absinthe.Phase.ItemErrors.run(bp, [])

    assert Warden.Absinthe.Plugin.pipeline([], bp.execution) == []
  end

  test "two identical documents in one batch each fold and get only their own errors" do
    doc = "{ grid { rows { id hidden } } }"
    assert {:ok, results} = batch([doc, doc], viewer())

    for bp <- results do
      {:ok, bp, _} = Absinthe.Pipeline.run(bp, [Absinthe.Phase.Document.Result])
      assert bp.result.data == %{"grid" => %{"rows" => [[nil], [nil]]}}
      # Each document reports its own two denials, no more.
      assert length(bp.result.errors) == 2
    end
  end

  test "outside batch mode the same documents return" do
    assert run("{ box { secrets { id } locked } }", viewer(), schema: Schema).data == %{
             "box" => nil
           }

    result = run("{ grid { rows { id hidden } } }", viewer(), schema: Schema)
    assert result.data == %{"grid" => %{"rows" => [[nil], [nil]]}}
  end
end
