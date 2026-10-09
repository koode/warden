defmodule Warden.RedteamExec.ExecutionTest do
  # Red-team: execution model. Each test asserts the secure behaviour.
  use ExUnit.Case, async: false

  import Warden.RedteamExec.Helpers
  import Warden.Test.CompileHelpers

  alias Warden.RedteamExec.Data

  @schema Warden.RedteamExec.Schema

  setup do
    Process.delete(:rx_deny)
    Process.delete(:rx_actor_key)
    :ok
  end

  defp viewer, do: Data.user(:viewer, id: "v1")

  describe "deferred resolution never runs for a denied field" do
    test "Async: the task function is not started" do
      result = run("{ asyncAdmin }", viewer())
      assert result.data == %{"asyncAdmin" => nil}
      Process.sleep(50)
      assert ran() == []
    end

    test "Batch: the batch function is not called" do
      result = run("{ batchAdmin }", viewer())
      assert result.data == %{"batchAdmin" => nil}
      assert ran() == []
    end

    test "Dataloader: the resolver and the load do not run" do
      result = run("{ loaderAdmin { code } }", viewer())
      assert result.data == %{"loaderAdmin" => nil}
      assert ran() == []
    end

    test "a user 'cache' middleware on a denied field does not serve its value" do
      result = run("{ cachedAdmin }", viewer())
      assert result.data == %{"cachedAdmin" => nil}
    end
  end

  describe "values produced outside the resolver are still checked" do
    test "a Dataloader-loaded denied object is nulled" do
      result = run("{ loaderSecret { code } }", viewer())
      refute contains?(result, "ALPHA")
    end

    test "an Async-resolved denied object in a non-null position folds upward" do
      result = run("{ asyncSecret { code } }", viewer())
      refute contains?(result, "ALPHA")
      assert result.data == nil
    end

    test "a user middleware before the resolver that short-circuits with a denied object" do
      result = run("{ cachedSecret { code } }", viewer())
      refute contains?(result, "ALPHA")
    end

    test "a denied union member in a list is nulled" do
      result = run("{ search { ... on RxSecret { code } ... on RxPost { title } } }", viewer())
      refute contains?(result, "ALPHA")
      assert contains?(result, "Hello")
    end
  end

  describe "{:replace, value} from the denial handler" do
    test "a replacement value of a denied object type is still nulled" do
      Process.put(:rx_deny, fn
        %{kind: :field} -> {:replace, Data.secret()}
        d -> Warden.Authorizer.default_deny(d, Warden.RedteamExec.Authz.__warden_catalog__())
      end)

      result = run("{ replaced { code } }", viewer())
      refute contains?(result, "ALPHA")
      assert ran() == []
    end

    test "a replacement value carrying denied nested field data does not leak it" do
      Process.put(:rx_deny, fn
        %{kind: :field, field: :replaced_post} -> {:replace, Data.post()}
        d -> Warden.Authorizer.default_deny(d, Warden.RedteamExec.Authz.__warden_catalog__())
      end)

      result = run("{ replacedPost { title notes } }", viewer())
      assert get_in(result, [:data, "replacedPost", "title"]) == "Hello"
      refute contains?(result, "editor-notes")
    end

    test "a replacement list with denied items under :filter drops them" do
      Process.put(:rx_deny, fn
        %{kind: :field} -> {:replace, [Data.secret(), Data.secret2()]}
        d -> Warden.Authorizer.default_deny(d, Warden.RedteamExec.Authz.__warden_catalog__())
      end)

      result = run("{ replacedList { code } }", viewer())
      refute contains?(result, "ALPHA")
      refute contains?(result, "BRAVO")
    end

    test "{:replace, _} for an argument denial fails closed and does not run the resolver" do
      Process.put(:rx_deny, fn _ -> {:replace, "fake"} end)

      assert_raise Warden.PolicyError, fn ->
        run("{ guardedArg(filter: {includeHidden: true}) }", viewer())
      end

      assert ran() == []
    end

    test "{:replace, _} for an object denial fails closed" do
      Process.put(:rx_deny, fn _ -> {:replace, %{code: "FAKE"}} end)

      assert_raise Warden.PolicyError, fn -> run("{ secret(id: \"s1\") { code } }", viewer()) end
    end
  end

  describe "odd denial handler returns" do
    test "{:error, []} still nulls the field" do
      Process.put(:rx_deny, fn _ -> {:error, []} end)

      outcome =
        try do
          run("{ adminOnly secret(id: \"s1\") { code } }", viewer())
        rescue
          _ -> :raised
        end

      refute contains?(outcome, "admin-data")
      refute contains?(outcome, "ALPHA")
      assert ran() == []
    end

    test "{:ok, value} raises instead of granting" do
      Process.put(:rx_deny, fn _ -> {:ok, "granted?"} end)
      assert_raise Warden.PolicyError, fn -> run("{ adminOnly }", viewer()) end
      assert ran() == []
    end

    test "a raising handler does not run the resolver" do
      Process.put(:rx_deny, fn _ -> raise "handler exploded" end)
      assert_raise RuntimeError, fn -> run("mutation { nuke }", viewer()) end
      assert ran() == []
    end

    test ":null on a mutation does not run it" do
      Process.put(:rx_deny, fn _ -> :null end)
      result = run("mutation { nuke }", viewer())
      assert result == %{data: %{"nuke" => nil}}
      assert ran() == []
    end
  end

  describe "mutations" do
    test "a denied mutation selected through a fragment on the mutation root" do
      doc = """
      mutation { ...M }
      fragment M on RootMutationType { nuke }
      """

      run(doc, viewer())
      assert ran() == []
    end

    test "a mutation root type rule stops every mutation resolver" do
      schema =
        compile_schema(
          """
          query do
            field :x, :string
          end

          mutation do
            authorize role(:admin)

            field :wipe, :boolean do
              resolve fn _, _, %{context: c} -> send(c.test_pid, {:ran, :wipe}); {:ok, true} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )

      run("mutation { a: wipe b: wipe }", viewer(), schema: schema)
      assert ran() == []
    end

    test "user middleware/3 returning closures (runtime shim) does not run a denied mutation" do
      schema =
        compile_schema(
          """
          def middleware(middleware, _field, _object) do
            [fn res, _ -> res end | middleware]
          end

          query do
            field :x, :string
          end

          mutation do
            field :wipe, :boolean do
              authorize role(:admin)
              resolve fn _, _, %{context: c} -> send(c.test_pid, {:ran, :wipe}); {:ok, true} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )

      result = run("mutation { wipe }", viewer(), schema: schema)
      assert result.data == %{"wipe" => nil}
      assert ran() == []
    end
  end

  describe "schema pipeline tampering" do
    test "a later pipeline modifier that strips Warden middleware fails compilation" do
      name = unique("Warden.RedteamExec.Strip")

      code = """
      defmodule #{name}.Phase do
        use Absinthe.Phase
        def pipeline(p), do: Absinthe.Pipeline.insert_before(p, Absinthe.Phase.Schema.Compile, __MODULE__)
        def run(bp, _) do
          [sd] = bp.schema_definitions
          arts = Enum.map(sd.type_artifacts, fn
            %Absinthe.Type.Object{fields: fs} = o ->
              %{o | fields: Map.new(fs, fn {k, f} ->
                {k, %{f | middleware: Enum.reject(f.middleware, &Warden.Middleware.warden_entry?/1)}}
              end)}
            t -> t
          end)
          {:ok, %{bp | schema_definitions: [%{sd | type_artifacts: arts}]}}
        end
      end

      defmodule #{name} do
        use Absinthe.Schema
        use Warden.Schema, authorizer: Warden.RedteamExec.Authz
        @pipeline_modifier #{name}.Phase

        query do
          field :secret, :string do
            authorize role(:admin)
            resolve fn _, _, _ -> {:ok, "s"} end
          end
        end
      end
      """

      assert_raise CompileError, fn -> compile!(code) end
    end
  end

  describe "introspection guard" do
    test "__schema on a non-root object named \"Query\" is guarded by the introspection rule" do
      schema =
        compile_schema(
          """
          object :saved_query, name: "Query" do
            field :sql, :string
          end

          query do
            field :saved, :saved_query do
              resolve fn _, _, _ -> {:ok, %{sql: "select 1"}} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz, introspection: role(:admin)"
        )

      # Sanity: the root guard works.
      root = run("{ __schema { queryType { name } } }", viewer(), schema: schema)
      assert root.data == %{"__schema" => nil}

      result =
        run("{ saved { __schema { types { name } } } }", viewer(), schema: schema)

      refute contains?(result, "RootQueryType")
    end

    test "__type on a non-root object named \"Query\" is guarded by the introspection rule" do
      schema =
        compile_schema(
          """
          object :saved_query, name: "Query" do
            field :sql, :string
          end

          object :hidden_admin_type do
            field :launch_codes, :string
          end

          query do
            field :saved, :saved_query do
              resolve fn _, _, _ -> {:ok, %{sql: "select 1"}} end
            end
            field :h, :hidden_admin_type
          end
          """,
          "authorizer: Warden.RedteamExec.Authz, introspection: role(:admin)"
        )

      result =
        run(~s|{ saved { __type(name: "HiddenAdminType") { fields { name } } } }|, viewer(),
          schema: schema
        )

      refute contains?(result, "launchCodes")
    end
  end

  describe "denial vs. not found (existence oracle)" do
    test "a denied object and a missing object are indistinguishable to the client" do
      denied = run(~s|{ secret(id: "s1") { id } }|, viewer())
      missing = run(~s|{ secret(id: "nope") { id } }|, viewer())
      assert denied == missing
    end
  end

  describe "batched execution (Absinthe.Plug batch mode uses BatchResolver)" do
    test "a denied list item whose parent is folded away does not hang the batch" do
      doc = "{ box { secrets { id } locked } }"
      ctx = %{current_user: viewer(), test_pid: self()}

      pipeline =
        @schema
        |> Absinthe.Pipeline.for_document(context: ctx)
        |> Absinthe.Pipeline.before(Absinthe.Phase.Document.Execution.Resolution)

      {:ok, bp, _} = Absinthe.Pipeline.run(doc, pipeline)

      task =
        Task.async(fn -> Absinthe.Pipeline.BatchResolver.run([bp], schema: @schema) end)

      outcome = Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill)
      assert {:ok, [_]} = outcome
    end

    test "control: denied list items without a parent fold finish in batch mode" do
      ctx = %{current_user: viewer(), test_pid: self()}

      pipeline =
        @schema
        |> Absinthe.Pipeline.for_document(context: ctx)
        |> Absinthe.Pipeline.before(Absinthe.Phase.Document.Execution.Resolution)

      {:ok, bp, _} = Absinthe.Pipeline.run("{ box { secrets { id } } }", pipeline)

      task =
        Task.async(fn -> Absinthe.Pipeline.BatchResolver.run([bp], schema: @schema) end)

      assert {:ok, [_]} = Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill)
    end

    test "the same document outside batch mode returns and leaks nothing" do
      result = run("{ box { secrets { code } locked } }", viewer())
      assert result.data == %{"box" => nil}
      refute contains?(result, "ALPHA")
    end

    test "item errors from one batched document do not land in another document" do
      ctx = %{current_user: viewer(), test_pid: self()}

      pipeline =
        @schema
        |> Absinthe.Pipeline.for_document(context: ctx)
        |> Absinthe.Pipeline.before(Absinthe.Phase.Document.Execution.Resolution)

      {:ok, bp1, _} = Absinthe.Pipeline.run("{ box { secrets { id } } }", pipeline)
      # Second document: same path, but a field the viewer may see as null.
      {:ok, bp2, _} = Absinthe.Pipeline.run("{ box { secrets: label } }", pipeline)

      task =
        Task.async(fn -> Absinthe.Pipeline.BatchResolver.run([bp1, bp2], schema: @schema) end)

      assert {:ok, [_, out2]} = Task.yield(task, 2_000) || Task.shutdown(task, :brutal_kill)

      {:ok, %{result: r2}, _} =
        Absinthe.Pipeline.run(out2, [Absinthe.Phase.Document.Result])

      refute Map.has_key?(r2, :errors)
    end
  end

  describe "plugins/0 overridden by the user" do
    test "item errors and data hiding still work when plugins/0 omits the defaults" do
      # Decision 11: object denials default to :null; report them as item errors.
      Process.put(:rx_deny, fn
        %{kind: :object} ->
          {:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}

        denial ->
          Warden.Authorizer.default_deny(denial, Warden.RedteamExec.Authz.__warden_catalog__())
      end)

      schema =
        compile_schema(
          """
          def plugins, do: [Absinthe.Middleware.Async]

          object :s do
            authorize role(:admin)
            field :code, :string
          end

          query do
            field :list, list_of(:s) do
              resolve fn _, _, _ -> {:ok, [%{code: "ALPHA"}, %{code: "BRAVO"}]} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )

      result = run("{ list { code } }", viewer(), schema: schema)
      assert result.data == %{"list" => [nil, nil]}
      assert length(result.errors) == 2
    end
  end
end
