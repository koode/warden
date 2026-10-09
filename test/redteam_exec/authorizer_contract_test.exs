defmodule Warden.RedteamExec.AuthorizerContractTest do
  # Red-team: the authorizer contract (odd callback returns) and compile-time
  # validation. Each test asserts the secure behaviour.
  use ExUnit.Case, async: false

  import Warden.RedteamExec.Helpers
  import Warden.Test.CompileHelpers

  alias Warden.RedteamExec.Data

  setup do
    Process.delete(:rx_deny)
    Process.delete(:rx_actor_key)
    :ok
  end

  defp viewer, do: Data.user(:viewer, id: "v1")

  defp run_ctx(doc, ctx, opts \\ []) do
    run(doc, Map.get(ctx, :current_user), Keyword.put(opts, :context, ctx))
  end

  describe "subject/1" do
    test "a subject of `false` is not authenticated" do
      result = run_ctx("{ authed }", %{subject_fun: fn _ -> false end})
      refute contains?(result, "authed-data")
      assert ran() == []
    end

    test "a subject of {:error, _} from a failed token lookup is not authenticated" do
      # Decision 10: an error subject is a broken subject/1 contract and raises; the
      # request returns no data and no resolver runs.
      assert_raise Warden.PolicyError, ~r/subject\/1 returned \{:error, :expired\}/, fn ->
        run_ctx("{ authed }", %{subject_fun: fn _ -> {:error, :expired} end})
      end

      assert ran() == []
    end

    test "an anonymous subject never reaches roles/2, even when roles/2 would grant admin" do
      ctx = %{current_user: nil, roles_fun: fn _, _ -> [:admin] end}
      result = run_ctx("{ adminOnly }", ctx)
      assert result.data == %{"adminOnly" => nil}
      assert ran() == []
    end
  end

  describe "roles/2" do
    test "a MapSet of roles fails closed" do
      ctx = %{current_user: viewer(), roles_fun: fn _, _ -> MapSet.new([:admin]) end}
      assert_raise Warden.PolicyError, fn -> run_ctx("{ adminOnly }", ctx) end
      assert ran() == []
    end

    test "nil roles fail closed" do
      ctx = %{current_user: viewer(), roles_fun: fn _, _ -> nil end}
      assert_raise Warden.PolicyError, fn -> run_ctx("{ adminOnly }", ctx) end
    end

    test "string roles are not atoms and do not grant" do
      ctx = %{current_user: viewer(), roles_fun: fn _, _ -> ["admin"] end}
      assert run_ctx("{ adminOnly }", ctx).data == %{"adminOnly" => nil}
    end

    test ":all smuggled as a role from user data grants nothing" do
      ctx = %{current_user: viewer(), roles_fun: fn _, _ -> [:all] end}

      assert run_ctx("{ adminOnly permField }", ctx).data == %{
               "adminOnly" => nil,
               "permField" => nil
             }
    end

    test "nested and tuple roles do not grant" do
      ctx = %{
        current_user: viewer(),
        roles_fun: fn _, _ -> [[:admin], {:admin}, {:role, :admin}] end
      }

      assert run_ctx("{ adminOnly }", ctx).data == %{"adminOnly" => nil}
    end

    test "a raising roles/2 does not run the resolver" do
      ctx = %{current_user: viewer(), roles_fun: fn _, _ -> raise "db down" end}
      assert_raise RuntimeError, fn -> run_ctx("mutation { nuke }", ctx) end
      assert ran() == []
    end

    test "hierarchy does not carry :all down: an editor (implied by admin) lacks admin's :all" do
      ctx = %{current_user: Data.user(:editor, id: "e1")}
      assert run_ctx("{ permField }", ctx).data == %{"permField" => nil}
    end
  end

  describe "permissions/2" do
    test ":all from user data is dropped (permission catalog declared)" do
      ctx = %{current_user: viewer(), perms_fun: fn _, _ -> [:all] end}
      assert run_ctx("{ permField }", ctx).data == %{"permField" => nil}
    end

    test ":all from user data is dropped (no permission catalog)" do
      schema =
        compile_schema(
          """
          query do
            field :p, :string do
              authorize permission("anything")
              resolve fn _, _, _ -> {:ok, "granted"} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.NilCatalogAuthz"
        )

      user = %{id: "x", roles: [:viewer], permissions: [:all]}
      assert run("{ p }", user, schema: schema).data == %{"p" => nil}
    end

    test "an atom permission does not match a string permission rule" do
      ctx = %{current_user: viewer(), perms_fun: fn _, _ -> [:"secrets:read"] end}
      assert run_ctx("{ permField }", ctx).data == %{"permField" => nil}
    end

    test "a MapSet of permissions fails closed" do
      ctx = %{current_user: viewer(), perms_fun: fn _, _ -> MapSet.new(["secrets:read"]) end}
      assert_raise Warden.PolicyError, fn -> run_ctx("{ permField }", ctx) end
    end
  end

  describe "check/2" do
    for {label, value} <- [
          {"the string \"true\"", "true"},
          {":ok", :ok},
          {"{:ok, true}", {:ok, true}},
          {"1", 1},
          {"a list [true]", [true]}
        ] do
      test "a check returning #{label} fails closed without running the resolver" do
        ctx = %{current_user: viewer(), check_result: unquote(Macro.escape(value))}
        assert_raise Warden.PolicyError, fn -> run_ctx("{ oddCheck }", ctx) end
        assert ran() == []
      end
    end

    test "a raising check does not run the resolver" do
      assert_raise RuntimeError, fn -> run("{ boomCheck }", viewer()) end
      assert ran() == []
    end
  end

  describe "error contents" do
    test "default errors reveal nothing beyond Forbidden for field, argument and object denials" do
      # Decision 11: object denials default to :null; report them so the test can check
      # every error says only Forbidden.
      Process.put(:rx_deny, fn
        %{kind: :object} ->
          {:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}

        denial ->
          Warden.Authorizer.default_deny(denial, Warden.RedteamExec.Authz.__warden_catalog__())
      end)

      result =
        run(
          ~s|{ adminOnly guardedArg(filter: {includeHidden: true}) secret(id: "s1") { code } }|,
          viewer()
        )

      for error <- result.errors do
        assert error.message == "Forbidden"
        assert error.extensions == %{code: "FORBIDDEN"}
      end

      assert length(result.errors) == 3
    end

    test "expose_denial_reasons lists only missing roles/permissions, never checks or held roles" do
      name = unique("Warden.RedteamExec.ExposeAuthz")

      compile!("""
      defmodule #{name} do
        use Warden.Authorizer,
          roles: [:admin, :viewer],
          checks: [:self],
          expose_denial_reasons: true

        def subject(c), do: c[:current_user]
        def roles(u, _), do: u.roles
        def check(:self, _), do: false
      end
      """)

      schema =
        compile_schema(
          """
          query do
            field :x, :string do
              authorize any_of([role(:admin), check(:self)])
              resolve fn _, _, _ -> {:ok, "x"} end
            end
          end
          """,
          "authorizer: #{name}"
        )

      result = run("{ x }", Data.user(:viewer, id: "v"), schema: schema)
      [error] = result.errors
      assert error.extensions.missing_roles == ["admin"]
      refute inspect(error) =~ "self"
      refute inspect(error) =~ "viewer"
    end
  end

  describe "compile-time validation" do
    test "an undeclared check in authorize_args fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          query do
            field :x, :string do
              arg :a, :boolean
              authorize_args a: check(:nope)
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )
      end
    end

    test "an undeclared check in an input field rule fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          input_object :inp do
            field :f, :boolean do
              authorize check(:nope)
            end
          end

          query do
            field :x, :string do
              arg :i, :inp
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )
      end
    end

    test "an undeclared check in an interface field rule fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          interface :named do
            field :name, :string do
              authorize check(:nope)
            end
            resolve_type fn _, _ -> :thing end
          end

          object :thing do
            interface :named
            field :name, :string
          end

          query do
            field :t, :thing
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )
      end
    end

    test "an unknown role nested deep inside any_of/all_of fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          query do
            field :x, :string do
              authorize any_of([role(:viewer), all_of([authenticated(), role(:superuser)])])
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )
      end
    end

    test "a default_object_rule naming an unknown role fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          query do
            field :x, :string
          end
          """,
          "authorizer: Warden.RedteamExec.Authz, default_object_rule: role(:superuser)"
        )
      end
    end

    test "an introspection rule naming an undeclared check fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          query do
            field :x, :string
          end
          """,
          "authorizer: Warden.RedteamExec.Authz, introspection: check(:nope)"
        )
      end
    end

    test "a role hierarchy cycle fails compilation" do
      assert_raise CompileError, fn ->
        compile!("""
        defmodule #{unique("Warden.RedteamExec.CycleAuthz")} do
          use Warden.Authorizer,
            roles: [:a, :b, :c],
            role_hierarchy: %{a: [:b], b: [:c], c: [:a]}
          def subject(c), do: c[:current_user]
          def roles(u, _), do: u.roles
        end
        """)
      end
    end

    test "a self-loop in the role hierarchy fails compilation" do
      assert_raise CompileError, fn ->
        compile!("""
        defmodule #{unique("Warden.RedteamExec.LoopAuthz")} do
          use Warden.Authorizer, roles: [:a], role_hierarchy: %{a: [:a]}
          def subject(c), do: c[:current_user]
          def roles(u, _), do: u.roles
        end
        """)
      end
    end

    test "a raw meta warden_rule that is not a valid rule fails compilation" do
      assert_raise CompileError, fn ->
        compile_schema(
          """
          query do
            field :x, :string do
              meta warden_rule: true
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )
      end
    end

    test "a hydrate rule on a field argument is enforced or rejected, never ignored" do
      name = unique("Warden.RedteamExec.ArgHydrate")

      outcome =
        try do
          compile!("""
          defmodule #{name} do
            use Absinthe.Schema
            use Warden.Schema, authorizer: Warden.RedteamExec.Authz

            import_sdl \"\"\"
            type Query {
              salary(raw: Boolean = false): String
            }
            \"\"\"

            alias Absinthe.Blueprint.Schema.{FieldDefinition, InputValueDefinition}

            def hydrate(%InputValueDefinition{identifier: :raw}, [%FieldDefinition{identifier: :salary} | _]) do
              [Warden.Hydrate.meta(rule: role(:admin))]
            end

            def hydrate(%FieldDefinition{identifier: :salary}, _) do
              [{:resolve, &__MODULE__.salary/2}]
            end

            def hydrate(_, _), do: []
            def salary(_, _), do: {:ok, "SALARY"}
          end
          """)

          :compiled
        rescue
          CompileError -> :rejected
        end

      if outcome == :compiled do
        result = run("{ salary(raw: true) }", viewer(), schema: Module.concat([name]))
        refute contains?(result, "SALARY")
      end
    end

    test "a later {:meta, _} hydration does not silently drop a Warden rule" do
      name = unique("Warden.RedteamExec.MetaReplace")

      outcome =
        try do
          compile!("""
          defmodule #{name} do
            use Absinthe.Schema
            use Warden.Schema, authorizer: Warden.RedteamExec.Authz

            import_sdl \"\"\"
            type Query {
              salary: String
            }
            \"\"\"

            alias Absinthe.Blueprint.Schema.FieldDefinition

            def hydrate(%FieldDefinition{identifier: :salary}, _) do
              [
                Warden.Hydrate.meta(rule: role(:admin)),
                {:meta, [cache: false]},
                {:resolve, &__MODULE__.salary/2}
              ]
            end

            def hydrate(_, _), do: []
            def salary(_, _), do: {:ok, "SALARY"}
          end
          """)

          :compiled
        rescue
          CompileError -> :rejected
        end

      if outcome == :compiled do
        result = run("{ salary }", viewer(), schema: Module.concat([name]))
        refute contains?(result, "SALARY")
      end
    end

    test "a catalog role named :all grants no permissions" do
      name = unique("Warden.RedteamExec.AllRoleAuthz")

      compile!("""
      defmodule #{name} do
        use Warden.Authorizer, roles: [:all, :viewer], permissions: ["p"]
        def subject(c), do: c[:current_user]
        def roles(u, _), do: u.roles
      end
      """)

      schema =
        compile_schema(
          """
          query do
            field :x, :string do
              authorize permission("p")
              resolve fn _, _, _ -> {:ok, "granted"} end
            end
          end
          """,
          "authorizer: #{name}"
        )

      assert run("{ x }", Data.user(:all, id: "z"), schema: schema).data == %{"x" => nil}
    end
  end
end
