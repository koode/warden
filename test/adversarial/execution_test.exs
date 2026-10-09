defmodule Warden.Adversarial.ExecutionTest do
  @moduledoc """
  Attempts to slip denied data past Warden through the execution machinery: user
  middleware, middleware/3, async resolution, resolver return shapes and checks.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  @schema Warden.Test.Adversarial.Schema

  defp adv(doc, user, opts \\ []), do: run(doc, user, Keyword.put(opts, :schema, @schema))

  test "user middleware after Absinthe.Resolution swaps in a restricted object" do
    result = adv("{ tamperedObject { code } }", viewer())
    assert result.data == %{"tamperedObject" => nil}
    assert [%{message: "Forbidden"}] = result.errors
  end

  test "user middleware that appends to the chain at runtime, after Warden's post" do
    result = adv("{ appended { code } }", viewer())
    assert result.data == %{"appended" => nil}
    refute contains?(result.data, "ALPHA")
  end

  test "user middleware/3 that drops all other middleware" do
    result = adv("{ dropped { code } }", viewer())
    assert result.data == %{"dropped" => nil}
    # The field rule ran before the user's resolver.
    assert resolved() == []

    assert adv("{ dropped { code } }", admin()).data == %{"dropped" => %{"code" => "ALPHA"}}
  end

  test "user middleware/3 that returns a closure (runtime shim) keeps post checks" do
    result = adv("{ closure { code } }", viewer())
    assert result.data == %{"closure" => nil}

    [field_mw] =
      Absinthe.Schema.lookup_type(@schema, :query).fields.closure.middleware
      |> Enum.filter(&match?({{Warden.Absinthe.Middleware, :shim}, _}, &1))

    assert field_mw
  end

  test "resolver returning {:middleware, ...} to run its own resolution step" do
    assert adv("{ deferred { code } }", viewer()).data == %{"deferred" => nil}
  end

  test "resolver returning a single object for a list type" do
    result = adv("{ notAList { code } }", viewer())
    assert result.data == %{"notAList" => [nil]}
  end

  test "concrete field returning an object whose interface has an object rule" do
    # :dossier has no rule of its own; its :classified interface requires admin.
    assert adv("{ dossier { body } }", viewer()).data == %{"dossier" => nil}
    assert adv("{ classified { id } }", viewer()).data == %{"classified" => nil}
    assert adv("{ dossier { body } }", admin()).data == %{"dossier" => %{"body" => "classified"}}
  end

  test "value whose concrete type cannot be resolved behind an interface" do
    assert adv("{ mystery { id } }", admin()).data == %{"mystery" => nil}
  end

  test "context rewritten to an admin by middleware mid-execution" do
    result = adv("{ escalate adminOnly }", viewer())
    assert result.data == %{"escalate" => "open", "adminOnly" => nil}
  end

  test "async, batch and dataloader resolution of denied objects" do
    doc = ~s|{ asyncSecret { code } batchSecrets { code } loaderSecret(id: "s1") { code } }|
    result = run(doc, viewer())
    refute contains?(result.data, "ALPHA")
    refute contains?(result.data, "BRAVO")
  end

  test "truthy non-boolean check returns" do
    for truthy <- [:ok, {:ok, true}, "yes", 1, "true", [], %{}, :true_ish] do
      assert_raise Warden.PolicyError, fn ->
        run("{ configured }", viewer(), context: %{check_result: truthy})
      end
    end

    assert resolved() == []
  end

  test "nil check return" do
    assert_raise Warden.PolicyError, fn ->
      run("{ configured }", viewer(), context: %{check_result: nil})
    end
  end

  test "roles from user data outside the catalog" do
    result = run("{ adminStats }", viewer(), context: %{roles_fun: fn _ -> ["admin", :root] end})
    assert result.data == %{"adminStats" => nil}
  end

  test "denied mutation side effects" do
    result = run(~s|mutation { deletePost(id: "p1") }|, viewer())
    assert result.data == %{"deletePost" => nil}
    assert resolved() == []

    result = run(~s|mutation { createPost(title: "x", pinned: true) { id } }|, editor())
    assert result.data == %{"createPost" => nil}
    assert resolved() == []
  end

  test "denied mutation in a batch of mutations" do
    doc = ~s|mutation { a: deletePost(id: "p1") b: createPost(title: "x") { id } }|
    result = run(doc, editor())
    assert result.data == %{"a" => nil, "b" => %{"id" => "p9"}}
    assert resolved() == [{:create_post, %{title: "x", pinned: false}}]
  end
end
