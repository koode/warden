defmodule Warden.Adversarial.DocumentShapeTest do
  @moduledoc """
  Attempts to reach denied data by reshaping the document.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  alias Warden.Test.Data

  test "named fragment selecting a denied field" do
    doc = """
    { search { ...S } }
    fragment S on Secret { code }
    """

    result = run(doc, viewer())
    refute contains?(result.data, "ALPHA")
    refute contains?(result.data, "BRAVO")
  end

  test "nested fragments through an interface into a denied field" do
    doc = """
    { node(id: "u1") { ...N } }
    fragment N on Node { ... on User { ...U } }
    fragment U on User { email label }
    """

    result = run(doc, viewer())
    assert result.data == %{"node" => %{"email" => nil, "label" => nil}}
  end

  test "aliasing a denied field" do
    result = run("{ a: adminStats b: adminStats }", viewer())
    assert result.data == %{"a" => nil, "b" => nil}
    assert resolved() == []
  end

  test "aliasing a denied object in parallel with an allowed one" do
    result = run(~s|{ ok: user(id: "u2") { name } bad: secret { code } }|, viewer())
    assert result.data == %{"ok" => %{"name" => "Bob"}, "bad" => nil}
  end

  test "same field selected directly and through a fragment" do
    doc = "{ me { email ... on User { email } ...E } } fragment E on User { email }"
    assert run(doc, viewer()).data == %{"me" => %{"email" => "bob@example.com"}}
    assert run(doc, Data.as(:viewer, "u9")).data == %{"me" => nil}
  end

  test "interface field selection to reach a concrete field rule" do
    result = run(~s|{ node(id: "u3") { ... on Labeled { label } } }|, viewer())
    assert result.data == %{"node" => %{"label" => nil}}
  end

  test "union member selection to reach a denied type" do
    result = run("{ search { ... on Secret { id code } } }", viewer())
    secrets = Enum.drop(result.data["search"], 6)
    assert secrets == [nil, nil]
  end

  test "__typename on a denied object" do
    for doc <- [
          "{ secret { __typename } }",
          "{ secrets { __typename } }",
          ~s|{ node(id: "s1") { __typename } }|,
          "{ search { __typename } }"
        ] do
      result = run(doc, viewer())
      refute contains?(result.data, "Secret"), doc
    end
  end

  test "__typename on a denied list item of a union" do
    result = run("{ restricted { __typename } }", viewer())
    assert Enum.all?(result.data["restricted"], &is_nil/1)
  end

  test "Relay-style node lookup of a denied object" do
    result = run(~s|{ node(id: "s2") { id ... on Secret { code } } }|, viewer())
    assert result.data == %{"node" => nil}
  end

  test "Relay-style node lookup of an object visible only to its owner" do
    # Users are visible to viewers or to themselves.
    assert run(~s|{ node(id: "u4") { id } }|, nobody()).data == %{"node" => %{"id" => "u4"}}
    assert run(~s|{ node(id: "u1") { id } }|, nobody()).data == %{"node" => nil}
  end

  test "nested lists hiding a denied object at depth" do
    result = run("{ secretMatrix { code } }", viewer())
    refute contains?(result.data, "ALPHA")
    refute contains?(result.data, "BRAVO")
  end

  test "denied object deep inside allowed objects" do
    # friends are users; nobody (u4) sees only themselves.
    result = run("{ me { friends { id email } } }", nobody())
    assert result.data == %{"me" => %{"friends" => nil}}
  end

  test "@include and @skip do not change enforcement" do
    doc = "query($x: Boolean!) { secret @include(if: $x) { code } adminStats @skip(if: false) }"
    result = run(doc, viewer(), variables: %{"x" => true})
    assert result.data == %{"secret" => nil, "adminStats" => nil}
  end

  test "operation selection with several operations in one document" do
    doc = "query A { open } query B { adminStats }"

    {:ok, result} =
      Absinthe.run(doc, Warden.Test.Schema,
        operation_name: "B",
        context: %{current_user: viewer()}
      )

    assert result.data == %{"adminStats" => nil}
  end
end
