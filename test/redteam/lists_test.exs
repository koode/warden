defmodule Warden.Redteam.ListsTest do
  @moduledoc """
  Red team, query-shape lens: list shapes, list policies, null folding and error paths.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  @schema Warden.Redteam.ShapeSchema

  defp q(doc, user, opts \\ []), do: run(doc, user, Keyword.put(opts, :schema, @schema))

  # Decision 11: object denials default to :null. These tests check where errors land,
  # so they report object denials with Forbidden through the test handler.
  defp reporting(user) do
    Map.put(user, :deny_fun, fn
      %{kind: :object, list_policy: policy} when policy != :filter ->
        {:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}

      _ ->
        :default
    end)
  end

  defp paths(r), do: r |> Map.get(:errors, []) |> Enum.map(& &1[:path]) |> Enum.sort()

  test "[T!]! with a denied item folds up to data: null and leaks nothing" do
    r = q(~s|{ secretsNn { code } query }|, viewer())
    assert r.data == nil
    refute contains?(r, "ALPHA")
    refute contains?(r, "BRAVO")
  end

  test "[T!]! inside a nullable object folds to that object, siblings survive the sibling field" do
    r = q(~s|{ wrapper { label items { __typename } } other: wrapper { label } }|, viewer())
    assert r.data == %{"wrapper" => nil, "other" => %{"label" => "W"}}
  end

  test "[[T!]] with a denied item in the second inner list leaks nothing" do
    r = q(~s|{ secretsNested { code } }|, viewer())
    refute contains?(r.data, "ALPHA")
    refute contains?(r.data, "BRAVO")
  end

  test "[[Node]!]! null_item: denied items are null and error paths point at those items" do
    r = q(~s|{ g: grid { id } }|, reporting(viewer()))

    assert r.data == %{
             "g" => [
               [%{"id" => "t1"}, %{"id" => "t2"}],
               [%{"id" => "t1"}, nil, nil]
             ]
           }

    assert paths(r) == [["g", 1, 1], ["g", 1, 2]]
  end

  test ":filter on nested lists removes denied items at every depth without errors" do
    r = q(~s|{ gridFilter { id } }|, viewer())
    assert r.data == %{"gridFilter" => [[], [%{"id" => "t1"}, %{"id" => "t2"}]]}
    assert Map.get(r, :errors) == nil
  end

  test ":fail_list on nested lists fails the whole field" do
    r = q(~s|{ gridFail { id } }|, viewer())
    assert r.data == %{"gridFail" => nil}
    refute contains?(r.data, "t1")
  end

  test ":filter on a list of union members drops every denied member" do
    r =
      q(~s|{ searchFilter(ids: ["u1", "s1", "u2", "p1", "s2", "t1"]) { __typename } }|, viewer())

    assert r.data == %{
             "searchFilter" => [
               %{"__typename" => "User"},
               %{"__typename" => "Post"},
               %{"__typename" => "PublicThing"}
             ]
           }

    assert Map.get(r, :errors) == nil
  end

  test ":fail_list on a list of union members: one denied member hides the whole list" do
    r = q(~s|{ searchFail(ids: ["t1", "s1"]) { __typename } }|, viewer())
    assert r.data == %{"searchFail" => nil}
  end

  test ":null_item error paths use the alias of the list field" do
    r =
      q(
        ~s|{ a: search(ids: ["t1", "s1"]) { __typename } b: search(ids: ["s2"]) { __typename } }|,
        reporting(viewer())
      )

    assert r.data == %{"a" => [%{"__typename" => "PublicThing"}, nil], "b" => [nil]}
    assert paths(r) == [["a", 1], ["b", 0]]
  end

  test "single value given for a list argument still yields a checked list" do
    r = q(~s|{ search(ids: "s1") { ... on Secret { code } } }|, viewer())
    assert r.data == %{"search" => [nil]}
  end

  test ":filter error for one item does not land on another item or leak the original index" do
    # Secrets are reported with an error (kept as null), users are filtered silently.
    deny_fun = fn
      %{list_policy: :filter, type: :secret} -> {:error, "hidden"}
      %{list_policy: :filter} -> :null
      _ -> :default
    end

    user = Map.put(viewer(), :deny_fun, deny_fun)

    # u1 and u3 are filtered (not self); s1 is denied with an error.
    r = q(~s|{ searchFilter(ids: ["u1", "u3", "t1", "s1"]) { __typename } }|, user)
    assert r.data == %{"searchFilter" => [%{"__typename" => "PublicThing"}, nil]}
    assert paths(r) == [["searchFilter", 1]]
  end

  test ":filter error is reported even when a filtered item came before it" do
    deny_fun = fn
      %{list_policy: :filter, type: :secret} -> {:error, "hidden"}
      %{list_policy: :filter} -> :null
      _ -> :default
    end

    user = Map.put(viewer(), :deny_fun, deny_fun)
    r = q(~s|{ searchFilter(ids: ["u1", "s1"]) { __typename } }|, user)
    assert r.data == %{"searchFilter" => [nil]}
    assert [%{message: "hidden"}] = Map.get(r, :errors, [])
  end

  test ":filter error lands on the denied item, not on a later null item" do
    deny_fun = fn
      %{list_policy: :filter, type: :secret} -> {:error, "hidden"}
      %{list_policy: :filter} -> :null
      _ -> :default
    end

    user = Map.put(viewer(), :deny_fun, deny_fun)
    # u1 filtered, s1 denied with an error, "zz" does not exist (resolver returns nil).
    r = q(~s|{ searchFilter(ids: ["u1", "s1", "zz"]) { __typename } }|, user)
    assert r.data == %{"searchFilter" => [nil, nil]}
    assert paths(r) == [["searchFilter", 0]]
  end
end
