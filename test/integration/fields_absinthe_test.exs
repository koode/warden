defmodule Warden.FieldsAbsintheTest do
  use ExUnit.Case, async: true

  import Warden.Test.Fields.People
  import Warden.Test.CompileHelpers

  alias Warden.Absinthe.{Hydrate, Verifier}
  alias Warden.Test.Decisions
  alias Warden.Test.Fields.{Authz, Comment, Issue, UserCard}

  @schema Warden.Test.Fields.Schema
  @trashed ~U[2026-11-01 10:00:00Z]

  defp comment(id, extra \\ []) do
    base = %Comment{
      id: id,
      workspace_id: "t1",
      author_id: "abby",
      body: "body #{id}",
      anchor: "a#{id}"
    }

    struct!(base, extra)
  end

  defp run(document, user, extra, schema \\ @schema) do
    {:ok, result} = Absinthe.run(document, schema, context: context(user, extra))
    result
  end

  defp batch_calls do
    receive do
      {:check_many, name, count} -> [{name, count} | batch_calls()]
    after
      0 -> []
    end
  end

  defp flush_checks do
    receive do
      {:check_many, _name, _count} -> flush_checks()
      {:check, _name} -> flush_checks()
      {:tenant_roles, _user, _tenant} -> flush_checks()
      {:resolver_saw, _id, _body} -> flush_checks()
    after
      0 -> :ok
    end
  end

  describe "the object value is redacted before child fields resolve" do
    test "default and custom resolvers see the redacted struct" do
      comments = [comment(1, trashed_at: @trashed), comment(2)]

      result = run("{ comments { id body seenBody anchor } }", sam(), %{comments: comments})

      assert result == %{
               data: %{
                 "comments" => [
                   %{"id" => "1", "body" => "", "seenBody" => "", "anchor" => nil},
                   %{"id" => "2", "body" => "body 2", "seenBody" => "body 2", "anchor" => "a2"}
                 ]
               }
             }

      assert_received {:resolver_saw, 1, ""}
      assert_received {:resolver_saw, 2, "body 2"}
    end

    test "every rule runs once per list, and the batched object rule is not decided again per field" do
      comments = [comment(1), comment(2, trashed_at: @trashed), comment(3)]

      _result =
        run("{ comments { body anchor authorId seenBody } }", olivia(), %{comments: comments})

      assert Enum.sort(batch_calls()) == [live: 3, readable: 3]
    end

    test "tenant-role rules use the value's tenant" do
      comments = [
        comment(1, author_id: "sam", workspace_id: "t1"),
        comment(2, author_id: "sam", workspace_id: "t2"),
        comment(3, author_id: "abby", workspace_id: "t2")
      ]

      result = run("{ comments { authorId } }", abby(), %{comments: comments})

      assert result.data["comments"] == [
               %{"authorId" => "sam"},
               %{"authorId" => nil},
               %{"authorId" => "abby"}
             ]
    end

    test "a denied object stays null and is not redacted" do
      comments = [comment(1, hidden: true), comment(2, trashed_at: @trashed)]
      result = run("{ comments { body } }", abby(), %{comments: comments})
      assert result.data["comments"] == [nil, %{"body" => ""}]
    end

    test "an object type without an object rule is redacted too" do
      cards = [
        %UserCard{id: 1, tenant_id: "t1", timezone: "UTC", email: "e"},
        %UserCard{id: 2, tenant_id: "t2", timezone: "CET", email: "f"}
      ]

      result = run("{ cards { timezone email } }", sam(), %{cards: cards})

      assert result.data["cards"] == [
               %{"timezone" => "UTC", "email" => nil},
               %{"timezone" => nil, "email" => nil}
             ]
    end

    test "a value of another type than the policy's struct raises" do
      secret = "a secret body"
      value = %{id: 1, body: secret, hidden: false}

      error =
        assert_raise Warden.PolicyError, fn ->
          run("{ comments { body } }", abby(), %{comments: [value]})
        end

      refute Exception.message(error) =~ secret
    end
  end

  describe "adversarial documents" do
    test "aliases and fragments selecting the same field twice all read the redacted value" do
      document = """
      {
        first: comment { body again: body ...Parts }
        second: comment { ... on Comment { body anchor } }
      }
      fragment Parts on Comment { body anchor seenBody }
      """

      result = run(document, abby(), %{comments: [comment(1, trashed_at: @trashed)]})

      assert result.data == %{
               "first" => %{"body" => "", "again" => "", "anchor" => nil, "seenBody" => ""},
               "second" => %{"body" => "", "anchor" => nil}
             }
    end

    test "an interface field reaches the redacted object" do
      nodes = [
        comment(1, trashed_at: @trashed),
        %UserCard{id: 2, tenant_id: "t1", timezone: "UTC"},
        %Issue{id: 3, tenant_id: "t2", title: "Plan"}
      ]

      document = """
      { nodes {
          id
          ... on Comment { body anchor }
          ... on UserCard { timezone }
          ... on Issue { title }
      } }
      """

      result = run(document, olivia(), %{nodes: nodes})

      assert result.data["nodes"] == [
               %{"id" => "1", "body" => "", "anchor" => nil},
               %{"id" => "2", "timezone" => nil},
               %{"id" => "3", "title" => "[private]"}
             ]
    end

    test "a union member is redacted, with one batch per rule" do
      nodes = [comment(1, trashed_at: @trashed), comment(2)]
      document = "{ search { ... on Comment { body } } }"

      result = run(document, abby(), %{nodes: nodes})

      assert result.data["search"] == [%{"body" => ""}, %{"body" => "body 2"}]
      assert Enum.sort(batch_calls()) == [live: 2, readable: 2]
    end

    test "a mutation payload returning the object is redacted" do
      document = "mutation { editComment { comment { body authorId } } }"
      result = run(document, olivia(), %{comments: [comment(1, trashed_at: @trashed)]})
      assert result.data["editComment"] == %{"comment" => %{"body" => "", "authorId" => nil}}
    end

    test "a nested list of the object is redacted per item, still one batch per rule" do
      comments = [comment(1, trashed_at: @trashed), comment(2), comment(3, trashed_at: @trashed)]

      result = run("{ commentGrid { body } }", abby(), %{comments: comments})

      assert result.data["commentGrid"] == [
               [%{"body" => ""}, %{"body" => "body 2"}],
               [%{"body" => ""}]
             ]

      assert Enum.sort(batch_calls()) == [live: 3, readable: 3]
    end

    test "registered structs inside a redacted object are redacted on their own fields" do
      issue = %Issue{
        id: 1,
        tenant_id: "t1",
        title: "Plan",
        comments: [comment(1, trashed_at: @trashed)],
        cards: [%UserCard{id: 2, tenant_id: "t1", timezone: "UTC"}]
      }

      document = "{ issue { title comments { body } cards { timezone } } }"

      assert run(document, olivia(), %{issue: issue}).data["issue"] == %{
               "title" => "Plan",
               "comments" => [%{"body" => ""}],
               "cards" => [%{"timezone" => nil}]
             }
    end

    test ":filter removes denied items without revealing their index; the rest are redacted" do
      comments = [comment(1, hidden: true), comment(2, trashed_at: @trashed), comment(3)]
      result = run("{ filteredComments { id body } }", abby(), %{comments: comments})

      assert result == %{
               data: %{
                 "filteredComments" => [
                   %{"id" => "2", "body" => ""},
                   %{"id" => "3", "body" => "body 3"}
                 ]
               }
             }
    end
  end

  describe "deferred values" do
    test "async, batch and Dataloader values are redacted" do
      comments = [comment(1, trashed_at: @trashed), comment(2)]

      document = """
      {
        asyncComments { body }
        batchedComment(id: 1) { body }
        loadedComment(id: 2) { body }
        other: loadedComment(id: 3) { body }
      }
      """

      result = run(document, abby(), %{comments: comments})

      assert result.data == %{
               "asyncComments" => [%{"body" => ""}, %{"body" => "body 2"}],
               "batchedComment" => %{"body" => ""},
               "loadedComment" => %{"body" => ""},
               "other" => %{"body" => "loaded 3"}
             }
    end

    test "cross-parent batching decides and redacts every parent's value at once" do
      comments = [comment(1, trashed_at: @trashed), comment(2), comment(3, hidden: true)]
      flush_checks()

      result =
        run(
          "{ posts { id comment { body authorId } } }",
          olivia(),
          %{comments: comments},
          Warden.Test.Fields.AcrossSchema
        )

      assert result.data["posts"] == [
               %{"id" => "1", "comment" => %{"body" => "", "authorId" => nil}},
               %{"id" => "2", "comment" => %{"body" => "body 2", "authorId" => nil}},
               %{"id" => "3", "comment" => nil}
             ]

      assert Enum.sort(batch_calls()) == [live: 2, readable: 3]
    end
  end

  test "telemetry reports layer :fields without values" do
    Decisions.attach()
    secret = "the secret body"
    comments = [comment(1, body: secret, trashed_at: @trashed)]

    _result = run("{ comments { body } }", abby(), %{comments: comments})

    events = collect_events()
    fields_events = for {_measurements, %{layer: :fields}} = event <- events, do: event
    assert [_first, _second] = fields_events
    refute inspect(events) =~ secret
  end

  describe "compile-time checks" do
    test "with: nil on a non-null field fails compilation" do
      body = """
      object :comment do
        redact_with Warden.Test.Fields.NilBodyFields
        field :body, non_null(:string)
        field :anchor, :string
      end

      query do
        field :comment, :comment
      end
      """

      error =
        assert_raise CompileError, fn ->
          compile_schema(body, "authorizer: Warden.Test.Fields.NilAuthz")
        end

      message = Exception.message(error)
      assert message =~ "Comment.body: Warden.Test.Fields.NilBodyFields redacts :body with nil"
      refute message =~ "Comment.anchor"
    end

    test "an unknown module fails compilation" do
      body = """
      object :comment do
        redact_with Warden.Test.Fields.Nope
        field :body, :string
      end

      query do
        field :comment, :comment
      end
      """

      assert_raise CompileError, ~r/`redact_with` needs a field policy/, fn ->
        compile_schema(body, "authorizer: Warden.Test.Fields.Authz")
      end
    end

    test "a field policy for another struct fails compilation" do
      body = """
      object :comment do
        authorize can(Warden.Test.Fields.Comments, :read)
        redact_with Warden.Test.Fields.UserCardFields
        field :body, :string
      end

      query do
        field :comment, :comment
      end
      """

      assert_raise CompileError,
                   ~r/redacts Warden.Test.Fields.UserCard, but the object type/,
                   fn ->
                     compile_schema(body, "authorizer: Warden.Test.Fields.Authz")
                   end
    end

    test "a field policy of another authorizer fails compilation" do
      body = """
      object :comment do
        redact_with Warden.Test.Fields.NilBodyFields
        field :body, :string
      end

      query do
        field :comment, :comment
      end
      """

      assert_raise CompileError, ~r/belongs to Warden.Test.Fields.NilAuthz/, fn ->
        compile_schema(body, "authorizer: Warden.Test.Fields.Authz")
      end
    end

    test "redact_with only goes on object types" do
      body = """
      interface :node do
        redact_with Warden.Test.Fields.CommentFields
        field :id, :id
      end

      query do
        field :node, :node
      end
      """

      assert_raise CompileError, ~r/`redact_with` must be used inside `object`/, fn ->
        compile_schema(body, "authorizer: Warden.Test.Fields.Authz")
      end
    end

    test "redact_with twice on one object fails compilation" do
      body = """
      object :comment do
        redact_with Warden.Test.Fields.CommentFields
        redact_with Warden.Test.Fields.CommentFields
        field :body, :string
      end

      query do
        field :comment, :comment
      end
      """

      assert_raise CompileError, ~r/`redact_with` is declared twice/, fn ->
        compile_schema(body, "authorizer: Warden.Test.Fields.Authz")
      end
    end

    test "Hydrate.meta/2 takes redact_with: for SDL schemas" do
      module = Warden.Test.Fields.CommentFields

      assert {:meta, [warden_redact_with: ^module]} =
               Hydrate.meta(redact_with: module)

      assert_raise ArgumentError, ~r/invalid redact_with/, fn ->
        Hydrate.meta(redact_with: "CommentFields")
      end
    end

    test "a valid schema verifies, and the plan gives the field its redactor" do
      assert :ok = Verifier.verify(@schema)
      field = Absinthe.Schema.lookup_type(@schema, :query).fields.cards
      [{{Warden.Absinthe.Middleware, :post}, spec}] = Enum.take(field.middleware, -1)
      assert spec.redactors == %{user_card: Warden.Test.Fields.UserCardFields}
    end
  end

  test "the core API and GraphQL agree on one struct" do
    card = %UserCard{id: 1, tenant_id: "t1", timezone: "UTC", email: "e"}
    redacted = Warden.redact(context(olivia()), card, authorizer: Authz)
    result = run("{ cards { timezone email } }", olivia(), %{cards: [card]})
    assert result.data["cards"] == [%{"timezone" => redacted.timezone, "email" => redacted.email}]
  end

  defp collect_events(acc \\ []) do
    receive do
      {:decision, measurements, metadata} -> collect_events([{measurements, metadata} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
