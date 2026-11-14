defmodule Warden.V2AbsintheTest do
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers
  import Warden.Test.Helpers, only: [resolved: 0]
  import Warden.Test.V2.People

  alias Warden.Absinthe.Hydrate
  alias Warden.Test.Decisions

  @schema Warden.Test.V2.Schema

  defp run(doc, user, extra \\ %{}, opts \\ []) do
    schema = Keyword.get(opts, :schema, @schema)

    {:ok, result} =
      Absinthe.run(doc, schema,
        context: context(user, extra),
        variables: Keyword.get(opts, :variables, %{})
      )

    result
  end

  defp messages(tag) do
    {:messages, messages} = Process.info(self(), :messages)
    for message <- messages, elem(message, 0) == tag, do: message
  end

  describe "can/2 as an object rule" do
    test "decides a whole list with one allowed_many/4 call" do
      result = run("{ docs { id } }", abby())
      assert result.data["docs"] == [%{"id" => 1}, nil, %{"id" => 3}, nil, %{"id" => 5}]
      refute Map.has_key?(result, :errors)
      assert messages(:allowed_many) == [{:allowed_many, :read, 5}]
      assert messages(:allowed?) == []
    end

    test "with list_policy :filter the denied items leave without revealing their index" do
      result = run("{ filteredDocs { id } }", sam())
      assert result.data["filteredDocs"] == [%{"id" => 2}, %{"id" => 3}, %{"id" => 5}]
      refute Map.has_key?(result, :errors)
    end
  end

  describe "batched checks on list items" do
    test "call check_many/2 once per list" do
      result = run("{ people { name } }", abby())
      assert result.data["people"] == [%{"name" => "Abby"}, nil, %{"name" => "Olivia"}]
      assert messages(:check_many) == [{:check_many, :visible, 3}]
    end

    test "across parents, one call per parent without batch_across_parents" do
      run("{ docs { owner { name } } }", abby())

      assert messages(:check_many) == [
               {:check_many, :visible, 1},
               {:check_many, :visible, 1},
               {:check_many, :visible, 1}
             ]
    end
  end

  describe "covered() and on_deny:" do
    test "covered fields resolve when the object rule passes" do
      assert run("{ docs { id body } }", abby()).data["docs"] |> hd() == %{
               "id" => 1,
               "body" => "doc body"
             }
    end

    test "on_deny: :null hides a denied field without an error" do
      owner = run("{ docs { id adminNote } }", abby())
      assert hd(owner.data["docs"]) == %{"id" => 1, "adminNote" => "note"}

      member = run("{ filteredDocs { id adminNote } }", sam())
      assert hd(member.data["filteredDocs"]) == %{"id" => 2, "adminNote" => nil}
      refute Map.has_key?(member, :errors)
    end

    test "on_deny: {:replace, value} replaces a denied non-null field" do
      assert hd(run("{ docs { badge } }", abby()).data["docs"]) == %{"badge" => "owner badge"}

      assert hd(run("{ filteredDocs { badge } }", sam()).data["filteredDocs"]) == %{
               "badge" => "hidden"
             }
    end
  end

  describe "tenant roles" do
    test "are read once per tenant per execution, across object and field rules" do
      result = run("{ workspaces { name guarded } }", abby())

      assert result.data["workspaces"] == [
               %{"name" => "Studio", "guarded" => "member data"},
               %{"name" => "Lab", "guarded" => nil}
             ]

      assert Enum.sort(messages(:tenant_roles)) ==
               [
                 {:tenant_roles, "abby", "t1"},
                 {:tenant_roles, "abby", "t2"},
                 {:tenant_roles, "abby", "t3"}
               ]
    end

    test "are read again in the next execution" do
      run("{ workspaces { name } }", sam())
      run("{ workspaces { name } }", sam())
      assert [_one, _two, _three, _four, _five, _six] = messages(:tenant_roles)
    end

    test "a tenant from an argument is checked before the resolver" do
      assert run(~s|{ workspaceSecret(workspaceId: "t1") }|, abby()).data == %{
               "workspaceSecret" => "secret"
             }

      assert resolved() == [:workspace_secret]

      denied = run(~s|{ workspaceSecret(workspaceId: "t2") }|, abby())
      assert denied.data == %{"workspaceSecret" => nil}
      assert [%{message: "Forbidden"}] = denied.errors
      assert resolved() == []
    end
  end

  describe "can/3 with arg: on mutations" do
    test "denies before the resolver runs" do
      denied = run("mutation { updateDoc(id: 2) { id } }", abby())
      assert denied.data == %{"updateDoc" => nil}
      assert resolved() == []

      assert run("mutation { updateDoc(id: 1) { id } }", abby()).data == %{
               "updateDoc" => %{"id" => 1}
             }

      assert resolved() == [{:update_doc, 1}]
    end

    test "as an argument rule, every id must be allowed" do
      assert run("mutation { archiveDocs(ids: [1, 3]) }", abby()).data == %{"archiveDocs" => true}
      assert resolved() == [{:archive_docs, [1, 3]}]

      denied = run("mutation { archiveDocs(ids: [1, 2]) }", abby())
      assert denied.data == %{"archiveDocs" => nil}
      assert resolved() == []

      variables = %{"ids" => [3, 4]}
      run("mutation($ids: [Int!]!) { archiveDocs(ids: $ids) }", abby(), %{}, variables: variables)
      assert resolved() == []
    end
  end

  describe "reasons" do
    test "never appear in the default response" do
      result =
        run("{ reasoned }", abby(), %{reasoned: {:deny, {:not_member, %{team: "team-crimson"}}}})

      assert [error] = result.errors
      assert error.message == "Forbidden"
      assert error.extensions == %{code: "FORBIDDEN"}
      refute inspect(result) =~ "not_member"
      refute inspect(result) =~ "team-crimson"
    end
  end

  describe "telemetry" do
    test "one :object event per field, a list counted once, no subject and no value" do
      Decisions.attach()
      run("{ docs { body } }", abby())
      {:messages, messages} = Process.info(self(), :messages)

      object_events =
        for {:decision, measurements, %{kind: :object} = metadata} <- messages,
            do: {measurements, metadata}

      assert [{%{count: 5, denied: 2}, %{layer: :absinthe, result: :deny, actor_kind: :user}}] =
               object_events

      for {:decision, _measurements, metadata} <- messages do
        refute inspect(metadata, limit: :infinity) =~ "doc body"
        refute inspect(metadata, limit: :infinity) =~ "abby"
      end
    end
  end

  describe "batch_across_parents: true" do
    setup do
      schema =
        compile_schema(
          """
            object :person do
              authorize check(:visible)
              field :name, :string
            end

            object :doc do
              field :id, :integer
              field :owner, :person do
                resolve fn doc, _args, _resolution -> {:ok, Warden.Test.V2.Data.person(doc.owner_id)} end
              end
              field :owner_required, non_null(:person) do
                resolve fn doc, _args, _resolution -> {:ok, Warden.Test.V2.Data.person(doc.owner_id)} end
              end
            end

            query do
              field :docs, list_of(:doc) do
                resolve fn _args, _resolution -> {:ok, Warden.Test.V2.Doc.all()} end
              end
              field :doc, :doc do
                resolve fn _args, _resolution -> {:ok, Warden.Test.V2.Doc.get(1)} end
              end
            end
          """,
          "authorizer: Warden.Test.V2.Authz, batch_across_parents: true"
        )

      %{schema: schema}
    end

    test "decides every parent's value at one level with one call", %{schema: schema} do
      result = run("{ docs { id owner { name } } }", abby(), %{}, schema: schema)

      assert Enum.map(result.data["docs"], & &1["owner"]) == [
               %{"name" => "Abby"},
               nil,
               %{"name" => "Abby"},
               %{"name" => "Olivia"},
               %{"name" => "Olivia"}
             ]

      assert messages(:check_many) == [{:check_many, :visible, 5}]
    end

    test "a denied non-null object still folds to the nullable parent", %{schema: schema} do
      result = run("{ docs { id ownerRequired { name } } }", abby(), %{}, schema: schema)
      assert Enum.at(result.data["docs"], 1) == nil

      assert Enum.at(result.data["docs"], 0) == %{
               "id" => 1,
               "ownerRequired" => %{"name" => "Abby"}
             }
    end

    test "a single object outside a list is decided at once", %{schema: schema} do
      assert run("{ doc { owner { name } } }", abby(), %{}, schema: schema).data == %{
               "doc" => %{"owner" => %{"name" => "Abby"}}
             }

      assert messages(:check_many) == [{:check_many, :visible, 1}]
    end

    test "needs Absinthe.Middleware.Batch in plugins/0" do
      assert_raise CompileError, ~r/needs Absinthe.Middleware.Batch/, fn ->
        compile_schema(
          """
            def plugins, do: [Absinthe.Middleware.Async]

            object :person do
              authorize check(:visible)
              field :name, :string
            end

            query do
              field :people, list_of(:person)
            end
          """,
          "authorizer: Warden.Test.V2.Authz, batch_across_parents: true"
        )
      end
    end
  end

  describe "hydrate" do
    test "Warden.Absinthe.Hydrate.meta/2 takes on_deny:" do
      assert {:meta, [warden_rule: :session, warden_on_deny: :null]} =
               Hydrate.meta(rule: :session, on_deny: :null)

      assert_raise ArgumentError, ~r/invalid on_deny/, fn ->
        Hydrate.meta(rule: :session, on_deny: :hide)
      end
    end
  end

  describe "compile-time validation" do
    defp compile_v2(body), do: compile_schema(body, "authorizer: Warden.Test.V2.Authz")

    test "covered() needs an object rule on the type" do
      assert_raise CompileError, ~r/Thing.name: covered\(\) needs an object rule on Thing/, fn ->
        compile_v2("""
          object :thing do
            field :name, :string do
              authorize covered()
            end
          end

          query do
            field :thing, :thing
          end
        """)
      end
    end

    test "covered() alone, never inside all_of/any_of, never as an object or argument rule" do
      error =
        assert_raise CompileError, fn ->
          compile_v2("""
            object :thing do
              authorize covered()
              field :name, :string do
                authorize any_of([covered(), session()])
              end
              field :tag, :string do
                arg :mode, :string
                authorize_args mode: covered()
              end
            end

            query do
              field :thing, :thing
            end
          """)
        end

      message = Exception.message(error)
      assert message =~ "Thing: covered() is only for fields"
      assert message =~ "Thing.name: covered() must be the whole field rule"
      assert message =~ "Thing.tag: covered() is not an argument rule"
    end

    test "covered() is accepted under an interface rule and counts as declared under :all" do
      schema =
        compile_schema(
          """
            interface :named do
              authorize session()
              field :name, :string do
                authorize covered()
              end
              resolve_type fn _value, _resolution -> :thing end
            end

            object :thing do
              authorize session()
              interface :named
              field :name, :string do
                authorize covered()
              end
            end

            query do
              field :thing, :named do
                authorize public()
                resolve fn _args, _resolution -> {:ok, %{name: "x"}} end
              end
            end
          """,
          "authorizer: Warden.Test.V2.Authz, strict_mode: :all"
        )

      assert run("{ thing { name } }", abby(), %{}, schema: schema).data == %{
               "thing" => %{"name" => "x"}
             }
    end

    test "on_deny: :null on a non-null field fails" do
      assert_raise CompileError, ~r/Thing.name: `on_deny: :null` on a non-null field/, fn ->
        compile_v2("""
          object :thing do
            field :name, non_null(:string) do
              authorize session(), on_deny: :null
            end
          end

          query do
            field :thing, :thing
          end
        """)
      end
    end

    test "on_deny: must be a known value and only on object fields" do
      assert_raise CompileError,
                   ~r/`on_deny:` must be :null, \{:replace, value\} or :error/,
                   fn ->
                     compile_v2("""
                       query do
                         field :a, :string do
                           authorize session(), on_deny: :hide
                         end
                       end
                     """)
                   end

      assert_raise CompileError, ~r/`authorize` must be used inside `field`/, fn ->
        compile_v2("""
          object :thing do
            authorize session(), on_deny: :null
            field :a, :string
          end

          query do
            field :thing, :thing
          end
        """)
      end

      assert_raise CompileError, ~r/`on_deny:` is not supported on input object fields/, fn ->
        compile_v2("""
          input_object :filter do
            field :q, :string do
              authorize session(), on_deny: :null
            end
          end

          query do
            field :a, :string do
              arg :filter, :filter
            end
          end
        """)
      end
    end

    test "unknown policies, actions, tenant roles and kinds fail" do
      error =
        assert_raise CompileError, fn ->
          compile_v2("""
            object :thing do
              authorize can(Warden.Test.V2.Docs, :delete)
              field :a, :string do
                authorize tenant_role(:viewer)
              end
              field :b, :string do
                authorize kind(:robot)
              end
              field :c, :string do
                authorize can(String, :read)
              end
              field :d, :string do
                authorize credential_scope("admin")
              end
            end

            query do
              field :thing, :thing
            end
          """)
        end

      message = Exception.message(error)
      assert message =~ "has no action :delete"
      assert message =~ "tenant role :viewer"
      assert message =~ "kind :robot"
      assert message =~ "String is not in the authorizer's `policies:`"
      assert message =~ ~s|credential scope "admin"|
    end
  end
end
