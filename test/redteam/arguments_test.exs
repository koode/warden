defmodule Warden.Redteam.ArgumentsTest do
  @moduledoc """
  Red team, query-shape lens: arguments, variables, defaults, enums, input objects.
  Each test asserts that the restricted value is refused and the resolver never runs.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  @schema Warden.Redteam.ShapeSchema

  defp q(doc, user, opts \\ []), do: run(doc, user, Keyword.put(opts, :schema, @schema))

  defp denied_posts(doc, opts \\ []) do
    r = q(doc, viewer(), opts)
    assert r.data == %{"posts" => nil}, inspect(r)
    refute_received {:resolved, :posts}
    r
  end

  test "enum argument literal different from its enum default" do
    denied_posts(~s|{ posts(status: DRAFT) { id } }|)
  end

  test "enum argument through an operation variable default" do
    denied_posts(~s|query($s: PostStatus = ARCHIVED) { posts(status: $s) { id } }|)
  end

  test "enum argument through a variable" do
    denied_posts(~s|query($s: PostStatus) { posts(status: $s) { id } }|,
      variables: %{"s" => "DRAFT"}
    )
  end

  test "enum argument default given explicitly is allowed (control)" do
    r = q(~s|{ posts(status: PUBLISHED) { id } }|, viewer())
    assert [_, _] = r.data["posts"]
  end

  test "nested input object two levels deep, literal" do
    denied_posts(~s|{ posts(filter: {nested: {deepFlag: true}}) { id } }|)
  end

  test "nested input object field with an enum default set to another value" do
    denied_posts(~s|{ posts(filter: {nested: {status: ARCHIVED}}) { id } }|)
  end

  test "nested input enum field set to explicit null to escape its default" do
    denied_posts(~s|{ posts(filter: {nested: {status: null}}) { id } }|)
  end

  test "list of input objects inside an input object" do
    denied_posts(~s|{ posts(filter: {children: [{}, {deepFlag: true}]}) { id } }|)
  end

  test "single input object coerced to a list inside an input object" do
    denied_posts(~s|{ posts(filter: {children: {deepFlag: true}}) { id } }|)
  end

  test "list of lists of input objects inside an input object" do
    denied_posts(~s|{ posts(filter: {grid: [[{}], [{deepFlag: true}]]}) { id } }|)
  end

  test "single input object coerced to a list of lists" do
    denied_posts(~s|{ posts(filter: {grid: {deepFlag: true}}) { id } }|)
  end

  test "whole input object through a variable" do
    denied_posts(~s|query($f: PostFilter) { posts(filter: $f) { id } }|,
      variables: %{"f" => %{"nested" => %{"deepFlag" => true}}}
    )
  end

  test "variable inside a list literal of input objects" do
    denied_posts(~s|query($f: PostFilter) { posts(filters: [{title: "a"}, $f]) { id } }|,
      variables: %{"f" => %{"revealDeleted" => true}}
    )
  end

  test "variable for a nested input field inside a literal object" do
    denied_posts(~s|query($d: Boolean) { posts(filter: {nested: {deepFlag: $d}}) { id } }|,
      variables: %{"d" => true}
    )
  end

  test "operation variable default for a nested input field inside a literal object" do
    denied_posts(~s|query($d: Boolean = true) { posts(filter: {nested: {deepFlag: $d}}) { id } }|)
  end

  test "variable explicitly null for a nested enum input field with a default" do
    denied_posts(~s|query($s: PostStatus) { posts(filter: {nested: {status: $s}}) { id } }|,
      variables: %{"s" => nil}
    )
  end

  test "operation variable default as a whole input object" do
    denied_posts(~s|query($f: PostFilter = {revealDeleted: true}) { posts(filter: $f) { id } }|)
  end

  test "input object reused on a mutation argument" do
    r = q(~s|mutation { updatePost(input: {revealDeleted: true}) }|, viewer())
    assert r.data == %{"updatePost" => nil}
    refute_received {:resolved, :update_post}
  end

  test "input object reused in a non-null list on a mutation, single value coerced" do
    r = q(~s|mutation { updatePost(inputs: {nested: {deepFlag: true}}) }|, viewer())
    assert r.data == %{"updatePost" => nil}
    refute_received {:resolved, :update_post}
  end

  test "allowed and denied calls of one field side by side through aliases" do
    r = q(~s|{ ok: posts { id } bad: posts(includeDrafts: true) { id } }|, viewer())
    assert r.data["bad"] == nil
    assert [_, _] = r.data["ok"]
    assert resolved() == [:posts]
  end

  test "duplicate argument in one field does not run the resolver" do
    r = q(~s|{ posts(status: PUBLISHED, status: DRAFT) { id } }|, viewer())
    refute contains?(Map.get(r, :data), "p1")
    refute_received {:resolved, :posts}
  end

  test "restricted argument on a nested object field through a variable default" do
    r = q(~s|query($h: Boolean = true) { folder { items(includeHidden: $h) { id } } }|, viewer())
    assert r.data == %{"folder" => %{"items" => nil}}
    refute_received {:resolved, {:folder_items, true}}
  end

  test "restricted argument in a fragment with a variable" do
    doc = """
    query($t: Boolean!) { ...P }
    fragment P on RootQueryType { posts(includeDrafts: $t) { id } }
    """

    denied_posts(doc, variables: %{"t" => true})
  end
end
