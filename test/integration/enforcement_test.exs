defmodule Warden.Integration.EnforcementTest do
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  alias Warden.Test.Data

  describe "field rules" do
    test "a denied field is null with a Forbidden error and its resolver does not run" do
      result = run("{ adminStats }", viewer())

      assert result.data == %{"adminStats" => nil}
      assert [error] = result.errors
      assert forbidden?(error)
      assert error.path == ["adminStats"]
      refute :admin_stats in resolved()
    end

    test "an allowed field resolves" do
      assert run("{ adminStats }", admin()).data == %{"adminStats" => "42"}
      assert :admin_stats in resolved()
    end

    test "authenticated() denies an anonymous actor" do
      result = run("{ users { id } }", nil)
      assert result.data == %{"users" => nil}
      assert error_paths(result) == [["users"]]
    end

    test "a field rule is checked against the parent value" do
      # draftNotes requires check(:owner): Bob (u2) owns p1, not p2.
      result = run("{ posts { id draftNotes } }", viewer())

      assert result.data == %{
               "posts" => [
                 %{"id" => "p1", "draftNotes" => "bob notes"},
                 %{"id" => "p2", "draftNotes" => nil}
               ]
             }

      assert error_paths(result) == [["posts", 1, "draftNotes"]]
    end

    test "role hierarchy: admin implies editor implies viewer" do
      assert run("{ me { label } }", admin()).data == %{"me" => %{"label" => "label:Alice"}}
    end
  end

  describe "interface field rules" do
    test "a concrete field without its own rule inherits the interface field rule" do
      result = run("{ me { label } }", viewer())
      assert result.data == %{"me" => %{"label" => nil}}
      assert error_paths(result) == [["me", "label"]]
    end

    test "selecting through the interface applies the same rule" do
      result = run(~s|{ node(id: "u2") { ... on Labeled { label } } }|, viewer())
      assert result.data == %{"node" => %{"label" => nil}}
      assert error_paths(result) == [["node", "label"]]

      result = run(~s|{ node(id: "u2") { ... on Labeled { label } } }|, editor())
      assert result.data == %{"node" => %{"label" => "label:Bob"}}
    end
  end

  describe "object rules" do
    test "a denied object is null, so __typename does not leak" do
      result = run("{ secret { __typename id } }", viewer())
      assert result.data == %{"secret" => nil}
      assert error_paths(result) == [["secret"]]
    end

    test "a denied non-null object folds to the nearest nullable parent" do
      result = run("{ requiredSecret { id } open }", viewer())
      assert result.data == nil
      assert error_paths(result) == [["requiredSecret"]]
    end

    test "list items: null_item nulls the item with an error at its index" do
      result = run("{ secrets { id } }", viewer())
      assert result.data == %{"secrets" => [nil, nil]}
      assert error_paths(result) == [["secrets", 0], ["secrets", 1]]
      assert Enum.all?(result.errors, &forbidden?/1)
    end

    test "list items of a non-null item type fold to the list field" do
      # users: [User!]; User needs viewer or self. Dan (u4) has no roles.
      result = run("{ users { id } }", nobody())
      assert result.data == %{"users" => nil}
      assert error_paths(result) == [["users", 0], ["users", 1], ["users", 2]]
    end

    test "a non-null list of non-null items folds past the field" do
      result = run("{ nonNullSecrets { id } open }", viewer())
      assert result.data == nil
      assert error_paths(result) == [["nonNullSecrets", 0], ["nonNullSecrets", 1]]
    end

    test "object rules run with the parent check on every field" do
      plan = Warden.Absinthe.plan(Warden.Test.Schema)
      {pre, _post} = plan.fields[{:user, :name}]
      assert [{:object, :user, _}] = pre.checks
    end

    test "allowed objects resolve" do
      result = run("{ secrets { id code } }", admin())

      assert result.data == %{
               "secrets" => [
                 %{"id" => "s1", "code" => "ALPHA"},
                 %{"id" => "s2", "code" => "BRAVO"}
               ]
             }

      refute Map.has_key?(result, :errors)
    end
  end

  describe "unions and interfaces" do
    test "a union applies each concrete type's rule per item" do
      result =
        run("{ search { __typename ... on Secret { code } ... on Post { title } } }", viewer())

      types = Enum.map(result.data["search"], &(&1 && &1["__typename"]))
      assert types == ["User", "User", "User", "User", "Post", "Post", nil, nil]
      refute contains?(result.data, "ALPHA")
      assert error_paths(result) == [["search", 6], ["search", 7]]
    end

    test "a union's own rule applies AND the concrete rule" do
      result = run("{ restricted { __typename } }", viewer())
      assert result.data == %{"restricted" => List.duplicate(nil, 6)}

      both = Data.as([:auditor, :viewer], "u7")
      result = run("{ restricted { __typename } }", both)
      assert Enum.all?(result.data["restricted"], & &1)
    end

    test "Relay-style node lookup applies the concrete type's rule" do
      result = run(~s|{ node(id: "s1") { id ... on Secret { code } } }|, viewer())
      assert result.data == %{"node" => nil}

      result = run(~s|{ node(id: "s1") { id ... on Secret { code } } }|, admin())
      assert result.data == %{"node" => %{"id" => "s1", "code" => "ALPHA"}}
    end

    test "nested lists of an interface fold per level" do
      # [[Node!]!]: p1 ok, s1 denied -> inner list cannot be null -> field null
      result = run("{ mixedMatrix { id } }", viewer())
      assert result.data == %{"mixedMatrix" => nil}
      assert error_paths(result) == [["mixedMatrix", 0, 1]]
    end
  end

  describe "list policies" do
    test ":filter removes denied items without an error" do
      result = run("{ filteredSecrets { id } }", viewer())
      assert result == %{data: %{"filteredSecrets" => []}}
    end

    test ":fail_list denies the whole list field" do
      result = run("{ strictSecrets { id } }", viewer())
      assert result.data == %{"strictSecrets" => nil}
      assert error_paths(result) == [["strictSecrets"]]
    end

    test "nested lists: nullable items are nulled per index" do
      result = run("{ secretMatrix { id } }", viewer())
      assert result.data == %{"secretMatrix" => [[nil, nil], [nil], []]}

      assert error_paths(result) == [
               ["secretMatrix", 0, 0],
               ["secretMatrix", 0, 1],
               ["secretMatrix", 1, 0]
             ]
    end

    test "nested lists with non-null items: Absinthe folds to the list field, errors kept" do
      # [[Secret!]]: per the spec only the inner lists would become null, but Absinthe's
      # null propagation nulls the whole field. Warden keeps every item error.
      result = run("{ secretMatrixNn { id } }", viewer())
      assert result.data == %{"secretMatrixNn" => nil}

      assert error_paths(result) == [
               ["secretMatrixNn", 0, 0],
               ["secretMatrixNn", 0, 1],
               ["secretMatrixNn", 1, 0]
             ]
    end
  end

  describe "argument rules" do
    test "a restricted argument with a non-default value denies before the resolver" do
      result = run("{ users(includeDeleted: true) { id } }", viewer())
      assert result.data == %{"users" => nil}
      assert error_paths(result) == [["users"]]
      assert resolved() == []
    end

    test "the default value, given explicitly or not, is allowed" do
      assert run("{ users(includeDeleted: false) { id } }", viewer()).data["users"]
      assert run("{ users { id } }", viewer()).data["users"]
    end

    test "variables are checked after substitution" do
      doc = "query($d: Boolean) { users(includeDeleted: $d) { id } }"
      assert run(doc, viewer(), variables: %{"d" => true}).data == %{"users" => nil}
      assert run(doc, viewer(), variables: %{"d" => false}).data["users"]
      assert run(doc, admin(), variables: %{"d" => true}).data["users"]
    end

    test "variable defaults are checked" do
      doc = "query($d: Boolean = true) { users(includeDeleted: $d) { id } }"
      assert run(doc, viewer()).data == %{"users" => nil}
    end

    test "an explicit null for an argument with a non-null default is restricted" do
      assert run("{ users(status: null) { id } }", viewer()).data == %{"users" => nil}
      assert run("{ users(status: PUBLISHED) { id } }", viewer()).data["users"]
      assert run("{ users(status: DRAFT) { id } }", editor()).data["users"]
    end

    test "input object field rules" do
      assert run("{ posts(filter: {includeDrafts: true}) { id } }", viewer()).data == %{
               "posts" => nil
             }

      assert run("{ posts(filter: {includeDrafts: false}) { id } }", viewer()).data["posts"]
      assert run("{ posts(filter: {includeDrafts: true}) { id } }", editor()).data["posts"]
    end

    test "nested input objects and lists of input objects" do
      deny = [
        ~s|{ posts(filter: {author: {internalId: "1"}}) { id } }|,
        ~s|{ posts(filter: {authors: [{name: "a"}, {internalId: "1"}]}) { id } }|,
        ~s|{ posts(filter: {nested: {nested: {includeDrafts: true}}}) { id } }|,
        ~s|{ posts(filters: [{title: "x"}, {includeDrafts: true}]) { id } }|
      ]

      for doc <- deny do
        result = run(doc, viewer())
        assert result.data == %{"posts" => nil}, doc
        [error] = result.errors
        assert forbidden?(error)
      end

      assert run(~s|{ posts(filter: {author: {name: "a"}}) { id } }|, viewer()).data["posts"]
      assert run(~s|{ posts(filter: {author: {internalId: "1"}}) { id } }|, admin()).data["posts"]
    end

    test "input object fields passed through a variable" do
      doc = "query($f: PostFilter) { posts(filter: $f) { id } }"
      vars = %{"f" => %{"nested" => %{"author" => %{"internalId" => "7"}}}}
      assert run(doc, editor(), variables: vars).data == %{"posts" => nil}
    end
  end

  describe "mutations" do
    test "a denied mutation does not run its resolver" do
      result = run(~s|mutation { deletePost(id: "p1") }|, viewer())
      assert result.data == %{"deletePost" => nil}
      assert resolved() == []
    end

    test "a denied mutation argument does not run the resolver" do
      result = run(~s|mutation { createPost(title: "t", pinned: true) { id } }|, editor())
      assert result.data == %{"createPost" => nil}
      assert resolved() == []

      result = run(~s|mutation { createPost(title: "t") { id title } }|, editor())
      assert result.data == %{"createPost" => %{"id" => "p9", "title" => "t"}}
    end

    test "nested input rule on a mutation" do
      doc = ~s|mutation { updateProfile(input: {name: "x", roles: ["admin"]}) { id } }|
      assert run(doc, viewer()).data == %{"updateProfile" => nil}
      assert resolved() == []
    end

    test "an object rule on a mutation's return type nulls the result (the mutation ran)" do
      result = run("mutation { leakSecret { id code } }", viewer())
      assert result.data == %{"leakSecret" => nil}
      assert :leak_secret in resolved()
    end
  end

  describe "async, batch and dataloader" do
    test "post middleware sees the final value of async, batch and dataloader fields" do
      result =
        run(
          ~s|{ asyncSecret { code } batchSecrets { code } loaderSecret(id: "s2") { code } }|,
          viewer()
        )

      assert result.data == %{
               "asyncSecret" => nil,
               "batchSecrets" => [nil, nil],
               "loaderSecret" => nil
             }

      assert error_paths(result) == [
               ["asyncSecret"],
               ["batchSecrets", 0],
               ["batchSecrets", 1],
               ["loaderSecret"]
             ]

      result =
        run(
          ~s|{ asyncSecret { code } batchSecrets { code } loaderSecret(id: "s2") { code } }|,
          admin()
        )

      assert result.data == %{
               "asyncSecret" => %{"code" => "ALPHA"},
               "batchSecrets" => [%{"code" => "ALPHA"}, %{"code" => "BRAVO"}],
               "loaderSecret" => %{"code" => "BRAVO"}
             }
    end
  end

  describe "checks" do
    test "only a literal true grants" do
      assert run("{ configured }", viewer(), context: %{check_result: true}).data == %{
               "configured" => "configured"
             }

      assert run("{ configured }", viewer(), context: %{check_result: false}).data == %{
               "configured" => nil
             }
    end

    test "a non-boolean check return raises Warden.PolicyError" do
      for bad <- [:ok, {:ok, true}, "yes", 1, nil, "true"] do
        assert_raise Warden.PolicyError, fn ->
          run("{ configured }", viewer(), context: %{check_result: bad})
        end
      end

      assert resolved() == []
    end
  end

  describe "actor" do
    test "roles/2 that does not return a list raises" do
      assert_raise Warden.PolicyError, ~r/must return a list/, fn ->
        run("{ adminStats }", viewer(), context: %{roles_fun: fn _ -> :admin end})
      end
    end

    test "unknown roles are dropped, never granted" do
      result =
        run("{ adminStats }", viewer(), context: %{roles_fun: fn _ -> [:superuser, :root] end})

      assert result.data == %{"adminStats" => nil}
    end
  end
end
