defmodule Warden.Absinthe.ExecutionActorTest do
  # The actor of a document execution is built once, before resolution, and every field
  # and resolver uses that one actor (`Warden.Absinthe.actor/1`).
  use ExUnit.Case, async: true

  alias Absinthe.Phase.Document.Execution.Resolution
  alias Absinthe.Pipeline
  alias Absinthe.Pipeline.BatchResolver

  defmodule Schema do
    use Absinthe.Schema
    use Warden.Absinthe, authorizer: Warden.Test.Authz

    query do
      field :open, :string do
        resolve &report/2
      end

      field :guarded, :string do
        authorize role(:viewer)
        resolve &report/2
      end
    end

    defp report(_args, resolution) do
      actor = Warden.Absinthe.actor(resolution)
      send(resolution.context.test_pid, {:resolver_actor, actor})
      {:ok, "ok"}
    end
  end

  defmodule PlainSchema do
    use Absinthe.Schema

    query do
      field :open, :string do
        resolve fn _args, resolution ->
          _actor = Warden.Absinthe.actor(resolution)
          {:ok, "ok"}
        end
      end
    end
  end

  defp context(roles_called \\ nil) do
    test_pid = self()

    roles_fun = fn user ->
      send(test_pid, {:roles_called, roles_called})
      user.roles
    end

    %{current_user: %{id: "u1", roles: [:viewer]}, test_pid: test_pid, roles_fun: roles_fun}
  end

  defp resolver_actors do
    receive do
      {:resolver_actor, actor} -> [actor | resolver_actors()]
    after
      0 -> []
    end
  end

  test "every field of one execution gets the actor built before resolution, once" do
    {:ok, %{data: data}} =
      Absinthe.run("{ open guarded other: open }", Schema, context: context())

    assert data == %{"open" => "ok", "guarded" => "ok", "other" => "ok"}

    assert [first, second, third] = resolver_actors()
    assert first.subject.id == "u1"
    assert Enum.uniq([first.instance, second.instance, third.instance]) == [first.instance]
    assert_received {:roles_called, nil}
    refute_received {:roles_called, nil}
  end

  test "a field without rules sees the actor too" do
    {:ok, %{data: %{"open" => "ok"}}} = Absinthe.run("{ open }", Schema, context: context())
    assert [%Warden.Actor{} = actor] = resolver_actors()
    assert actor.subject.id == "u1"
  end

  test "every execution builds its own actor" do
    {:ok, _result} = Absinthe.run("{ open }", Schema, context: context())
    {:ok, _result} = Absinthe.run("{ open }", Schema, context: context())
    assert [first, second] = resolver_actors()
    assert first.instance != second.instance
  end

  test "raises for a schema that does not use Warden" do
    assert_raise ArgumentError, ~r/does not `use Warden.Absinthe`/, fn ->
      Absinthe.run("{ open }", PlainSchema, context: context())
    end
  end

  describe "Absinthe.Pipeline.BatchResolver" do
    # The batch's shared execution has no schema when plugins see it, so the first field
    # rule builds the actor, and the documents of the batch share it.
    defp batch(documents) do
      pipeline =
        Schema
        |> Pipeline.for_document(context: context())
        |> Pipeline.before(Resolution)

      blueprints =
        for document <- documents do
          {:ok, blueprint, _phases} = Pipeline.run(document, pipeline)
          blueprint
        end

      BatchResolver.run(blueprints, schema: Schema)
    end

    test "resolvers after a field rule see the actor that rule built" do
      assert [_first, _second] = batch(["{ guarded open }", "{ open }"])
      assert [first, second, third] = resolver_actors()
      assert Enum.uniq([first.instance, second.instance, third.instance]) == [first.instance]
    end

    test "actor/1 raises before any field rule ran" do
      assert_raise Warden.PolicyError, ~r/BatchResolver/, fn -> batch(["{ open }"]) end
    end
  end

  describe "without plugin callbacks" do
    # A pipeline that runs resolution with `plugin_callbacks: false` skips the step that
    # builds the actor; the first field rule then builds it, as before 0.3.
    defp run_without_callbacks(document) do
      pipeline =
        Schema
        |> Pipeline.for_document(context: context())
        |> Pipeline.replace(Resolution, {Resolution, plugin_callbacks: false})

      Pipeline.run(document, pipeline)
    end

    test "a field rule builds the actor, and resolvers after it see that actor" do
      {:ok, %{result: %{data: data}}, _phases} = run_without_callbacks("{ guarded open }")
      assert data == %{"guarded" => "ok", "open" => "ok"}
      assert [first, second] = resolver_actors()
      assert first.instance == second.instance
    end

    test "actor/1 raises when no actor was built" do
      assert_raise Warden.PolicyError, ~r/no Warden actor yet/, fn ->
        run_without_callbacks("{ open }")
      end
    end
  end
end
