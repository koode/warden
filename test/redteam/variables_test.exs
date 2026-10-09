defmodule Warden.Redteam.VariablesTest do
  @moduledoc """
  Red team, query-shape lens: variables that are declared but not provided, provided
  but unused, and coerced across list levels.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  @schema Warden.Redteam.ShapeSchema

  defp q(doc, user, opts \\ []), do: run(doc, user, Keyword.put(opts, :schema, @schema))

  test "declared but unprovided variable falls back to the argument default (control)" do
    r = q(~s|query($s: PostStatus) { posts(status: $s) { id } }|, viewer())
    assert [_, _] = r.data["posts"]
  end

  test "unprovided variable for a nested enum input field falls back to its default (control)" do
    r = q(~s|query($s: PostStatus) { posts(filter: {nested: {status: $s}}) { id } }|, viewer())
    assert [_, _] = r.data["posts"]
  end

  test "extra variables that are not used cannot change a restricted argument" do
    r =
      q(~s|query($s: PostStatus) { posts(status: $s) { id } }|, viewer(),
        variables: %{"s" => "PUBLISHED", "status" => "DRAFT", "includeDrafts" => true}
      )

    assert [_, _] = r.data["posts"]
  end

  test "list variable of input objects with one restricted entry" do
    r =
      q(~s|query($fs: [PostFilter]) { posts(filters: $fs) { id } }|, viewer(),
        variables: %{"fs" => [%{"title" => "a"}, %{"nested" => %{"deepFlag" => true}}]}
      )

    assert r.data == %{"posts" => nil}
    refute_received {:resolved, :posts}
  end

  test "single object variable for a list of input objects" do
    r =
      q(~s|query($fs: [PostFilter]) { posts(filters: $fs) { id } }|, viewer(),
        variables: %{"fs" => %{"revealDeleted" => true}}
      )

    assert r.data == %{"posts" => nil}
    refute_received {:resolved, :posts}
  end

  test "restricted node id through a variable list" do
    r =
      q(~s|query($ids: [ID!]) { nodes(ids: $ids) { id } }|, viewer(),
        variables: %{"ids" => ["s1"]}
      )

    assert r.data == %{"nodes" => [nil]}
  end
end
