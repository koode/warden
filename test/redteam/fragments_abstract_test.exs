defmodule Warden.Redteam.FragmentsAbstractTest do
  @moduledoc """
  Red team, query-shape lens: fragments, field merging and abstract types.
  Every test asserts the secure behaviour, so a failing test is a bypass.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  @schema Warden.Redteam.ShapeSchema

  defp q(doc, user, opts \\ []), do: run(doc, user, Keyword.put(opts, :schema, @schema))

  describe "fragments" do
    test "inline fragment on a concrete type through node reaches a denied field" do
      r = q(~s|{ node(id: "u2") { ... on User { name email } } }|, viewer())
      assert r.data == %{"node" => %{"name" => "Bob", "email" => nil}}
      refute contains?(r.data, "bob@example.com")
    end

    test "inline fragment on an interface nested inside a fragment on another interface" do
      doc = ~s|{ node(id: "u2") { ... on Node { ... on Entity { secretNote } } } }|
      r = q(doc, viewer())
      refute contains?(r.data, "NOTE-u2")
    end

    test "named fragment spread on the root type selecting a denied list" do
      doc = """
      query { ...Root }
      fragment Root on RootQueryType { wrapper { items { code } } }
      """

      r = q(doc, viewer())
      refute contains?(r.data, "ALPHA")
      refute contains?(r.data, "BRAVO")
    end

    test "type condition that does not match the runtime type is not a back door" do
      doc = ~s|{ search(ids: ["s1", "t1"]) { ... on PublicThing { label } ... on Secret { code } } }|
      r = q(doc, viewer())
      refute contains?(r.data, "ALPHA")
      assert r.data["search"] |> Enum.at(1) == %{"label" => "T1"}
    end

    test "field merging: one secret selected through two fragments with different sub-selections" do
      doc = """
      { node(id: "s1") { ... on Secret { id } ...S } }
      fragment S on Secret { code }
      """

      r = q(doc, viewer())
      assert r.data == %{"node" => nil}
    end

    test "field merging: same alias for a denied field and an allowed field via fragments" do
      # Different fields under one response key are a validation error; no data may leak.
      doc = """
      { node(id: "u2") { ... on User { x: name } ...F } }
      fragment F on User { x: email }
      """

      r = q(doc, viewer())
      refute contains?(Map.get(r, :data), "bob@example.com")
    end

    test "fragment on the same owner via interface and concrete with nested owner" do
      doc = """
      { post(id: "p1") {
          ... on Entity { owner { ... on User { email } } }
          ... on Post { owner { ... on Entity { secretNote } } }
      } }
      """

      r = q(doc, viewer())
      refute contains?(r.data, "bob@example.com")
      refute contains?(r.data, "NOTE-u2")
    end

    test "deeply nested fragment cycle of inline fragments on the root type" do
      doc = """
      { ... on RootQueryType { ... on RootQueryType { ... on RootQueryType { query } } } }
      """

      r = q(doc, viewer())
      assert r.data == %{"query" => nil}
    end

    test "aliased __typename shadowing a denied field" do
      doc = ~s|{ node(id: "u2") { __typename: email } }|
      r = q(doc, viewer())
      refute contains?(Map.get(r, :data), "bob@example.com")
    end

    test "aliases that swap a denied and an allowed field" do
      r = q(~s|{ node(id: "u2") { ... on User { email: name name: email } } }|, viewer())
      assert r.data == %{"node" => %{"email" => "Bob", "name" => nil}}
    end
  end

  describe "abstract types" do
    test "interface object rule applies when the object is reached through another interface" do
      # Post has no own rule but implements :entity (authenticated()).
      r = q(~s|{ node(id: "p1") { id ... on Post { title } } }|, nil)
      assert r.data == %{"node" => nil}
    end

    test "interface object rule applies to an implementor reached through a union" do
      r = q(~s|{ search(ids: ["p1"]) { ... on Post { title } } }|, nil)
      assert r.data == %{"search" => [nil]}
    end

    test "interface object rule applies to an implementor reached through a list of another interface" do
      r = q(~s|{ nodes(ids: ["p1", "t1"]) { id } }|, nil)
      assert r.data == %{"nodes" => [nil, %{"id" => "t1"}]}
    end

    test "conflicting field rules from two interfaces are both enforced (admin without auditor)" do
      r = q(~s|{ auditable(id: "p1") { secretNote } }|, admin())
      assert r.data == %{"auditable" => %{"secretNote" => nil}}
    end

    test "conflicting field rules from two interfaces are both enforced (auditor without admin)" do
      r = q(~s|{ entity(id: "p1") { secretNote } }|, auditor())
      assert r.data == %{"entity" => %{"secretNote" => nil}}
    end

    test "interface that implements an interface: rule on the parent interface field still applies" do
      r = q(~s|{ named(id: "u2") { secretNote ... on NamedEntity { label } } }|, viewer())
      refute contains?(r.data, "NOTE-u2")
      assert r.data == %{"named" => %{"secretNote" => nil, "label" => "Bob"}}
    end

    test "interface that implements an interface: parent interface object rule applies to anonymous" do
      r = q(~s|{ named(id: "u2") { id label } }|, nil)
      assert r.data == %{"named" => nil}
    end

    test "interface field returning another interface: nested concrete object rule" do
      # user.owner returns a Secret through :entity.
      r = q(~s|{ named(id: "u2") { owner { id __typename } } }|, viewer())
      assert r.data == %{"named" => %{"owner" => nil}}
    end

    test "union object rule applies with a fragment on the member" do
      r = q(~s|{ adminResult { ... on PublicThing { label } __typename } }|, viewer())
      assert r.data == %{"adminResult" => nil}
    end

    test "union object rule on a filtered list hides every item, including allowed members" do
      r = q(~s|{ adminResults { __typename } }|, viewer())
      assert r.data == %{"adminResults" => []}
    end

    test "union resolved through is_type_of applies the member's rule" do
      r = q(~s|{ typed { __typename ... on TypedSecret { code } } }|, viewer())
      refute contains?(r.data, "ALPHA")
      refute contains?(r.data, "TypedSecret")
    end

    test "resolve_type returning a type outside the union does not reveal the restricted type" do
      r = q(~s|{ odd { __typename } }|, viewer())
      refute contains?(Map.get(r, :data), "Secret")
    end

    test "resolve_type returning a type that does not implement the interface does not reveal it" do
      r = q(~s|{ oddIface { __typename } }|, viewer())
      refute contains?(Map.get(r, :data), "Secret")
    end

    test "Relay node: id of a restricted object is not returned via the Node interface" do
      r = q(~s|{ a: node(id: "s1") { id } b: nodes(ids: ["s2", "t1"]) { id __typename } }|, viewer())
      assert r.data["a"] == nil
      refute contains?(r.data, "s2")
      refute contains?(r.data, "Secret")
    end

    test "interface argument rule is enforced on the implementing object's field" do
      r = q(~s|{ folder { items(includeHidden: true) { id } } }|, viewer())
      assert r.data == %{"folder" => %{"items" => nil}}
      refute_received {:resolved, {:folder_items, true}}
    end

    test "interface argument rule is enforced when selected through the interface" do
      r = q(~s|{ searchable { items(includeHidden: true) { id } } }|, viewer())
      assert r.data == %{"searchable" => %{"items" => nil}}
      refute_received {:resolved, {:folder_items, true}}
    end

    test "interface list_policy :filter is inherited by the implementing object's field" do
      r = q(~s|{ folder { secrets { id } } }|, viewer())
      assert r.data == %{"folder" => %{"secrets" => []}}
      assert Map.get(r, :errors) == nil
    end
  end

  describe "__typename and root types" do
    test "__typename inside a nested non-null list of a denied type" do
      r = q(~s|{ secretsNested { __typename } }|, viewer())
      refute contains?(r.data, "Secret")
    end

    test "__typename on a denied object reached through an interface" do
      r = q(~s|{ entity(id: "s1") { __typename } }|, viewer())
      assert r.data == %{"entity" => nil}
    end

    test "a query field returning the mutation root type cannot run a denied mutation" do
      r = q(~s|{ mutations { deleteUser(id: "u1") } }|, viewer())
      refute contains?(Map.get(r, :data), true)
      refute_received {:resolved, :delete_user}
    end

    test "fields named query, mutation, subscription and schema keep their rules" do
      r = q(~s|{ query mutation subscription schema }|, viewer())

      assert r.data == %{
               "query" => nil,
               "mutation" => nil,
               "subscription" => nil,
               "schema" => nil
             }
    end

    test "fields named like roots selected through a fragment on the root type" do
      doc = """
      { ...R }
      fragment R on RootQueryType { q: query m: mutation }
      """

      assert q(doc, viewer()).data == %{"q" => nil, "m" => nil}
    end

    test "denied mutation through a named fragment on the mutation root" do
      doc = """
      mutation { ...M }
      fragment M on RootMutationType { deleteUser(id: "u1") }
      """

      r = q(doc, viewer())
      assert r.data == %{"deleteUser" => nil}
      refute_received {:resolved, :delete_user}
    end

    test "@skip/@include combinations cannot drop the rule on a field selected twice" do
      doc = """
      query($t: Boolean!, $f: Boolean!) {
        node(id: "u2") {
          ... on User @include(if: $t) { email @skip(if: $f) }
          ... on User @skip(if: $f) { e2: email @include(if: $t) }
        }
      }
      """

      r = q(doc, viewer(), variables: %{"t" => true, "f" => false})
      refute contains?(r.data, "bob@example.com")
    end
  end
end
