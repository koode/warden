defmodule Warden.Adversarial.ArgumentsTest do
  @moduledoc """
  Attempts to use restricted arguments and input fields.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  test "restricted argument through a variable" do
    doc = "query($d: Boolean) { users(includeDeleted: $d) { id } }"
    assert run(doc, viewer(), variables: %{"d" => true}).data == %{"users" => nil}
    assert resolved() == []
  end

  test "restricted argument through a variable default" do
    doc = "query($d: Boolean = true) { users(includeDeleted: $d) { id } }"
    assert run(doc, viewer()).data == %{"users" => nil}
  end

  test "restricted argument with an explicit null to escape a non-null default" do
    doc = "query($s: Status) { users(status: $s) { id } }"
    assert run(doc, viewer(), variables: %{"s" => nil}).data == %{"users" => nil}
  end

  test "restricted input field nested in a variable" do
    doc = "query($f: PostFilter) { posts(filter: $f) { id } }"

    for vars <- [
          %{"f" => %{"includeDrafts" => true}},
          %{"f" => %{"author" => %{"internalId" => "1"}}},
          %{"f" => %{"nested" => %{"nested" => %{"author" => %{"internalId" => "1"}}}}},
          %{"f" => %{"authors" => [%{"name" => "a"}, %{"internalId" => "1"}]}}
        ] do
      assert run(doc, viewer(), variables: vars).data == %{"posts" => nil}, inspect(vars)
    end

    assert resolved() == []
  end

  test "restricted input field in a list of input objects" do
    doc = "query($fs: [PostFilter]) { posts(filters: $fs) { id } }"
    vars = %{"fs" => [%{"title" => "x"}, %{"nested" => %{"includeDrafts" => true}}]}
    assert run(doc, viewer(), variables: vars).data == %{"posts" => nil}
  end

  test "single input object given for a list argument" do
    # GraphQL input coercion wraps a single value into a list.
    doc = ~s|{ posts(filters: {includeDrafts: true}) { id } }|
    assert run(doc, viewer()).data == %{"posts" => nil}
  end

  test "restricted input field set to null to escape a non-null default" do
    doc = ~s|{ posts(filter: {includeDrafts: null}) { id } }|
    assert run(doc, viewer()).data == %{"posts" => nil}
  end

  test "restricted mutation input field" do
    doc = ~s|mutation { updateProfile(input: {roles: ["admin"]}) { id } }|
    assert run(doc, viewer()).data == %{"updateProfile" => nil}
    assert resolved() == []
  end
end
