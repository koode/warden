defmodule Warden.CompileTest do
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers

  @query """
    query do
      field :ok, :string
    end
  """

  describe "rule validation" do
    test "a role outside the catalog fails compilation" do
      assert_raise CompileError,
                   ~r/role :superuser is not in the authorizer's role catalog/,
                   fn ->
                     compile_schema("""
                       query do
                         field :a, :string do
                           authorize role(:superuser)
                         end
                       end
                     """)
                   end
    end

    test "a permission outside the catalog fails compilation" do
      assert_raise CompileError,
                   ~r/permission "posts:delete" is not in the authorizer's permission catalog/,
                   fn ->
                     compile_schema("""
                       query do
                         field :a, :string do
                           authorize any_of([role(:admin), permission("posts:delete")])
                         end
                       end
                     """)
                   end
    end

    test "an undeclared check fails compilation" do
      assert_raise CompileError, ~r/check\(:nope\) is not declared/, fn ->
        compile_schema("""
          query do
            field :a, :string do
              authorize check(:nope)
            end
          end
        """)
      end
    end

    test "every problem is reported, not only the first" do
      error =
        assert_raise CompileError, fn ->
          compile_schema("""
            object :thing do
              authorize role(:ghost)
              field :x, :string do
                authorize permission("nope")
              end
            end

            query do
              field :thing, :thing
              field :a, :string do
                arg :id, :id
                authorize_args id: role(:phantom), missing: role(:admin)
              end
            end
          """)
        end

      message = Exception.message(error)
      assert message =~ "Thing: role :ghost"
      assert message =~ "Thing.x: permission \"nope\""
      assert message =~ "RootQueryType.a(id): role :phantom"
      assert message =~ "`authorize_args` names :missing, which is not an argument"
    end

    test "an invalid rule shape fails at the macro" do
      assert_raise CompileError, ~r/invalid rule in `authorize`: invalid rule: :admin/, fn ->
        compile_schema("""
          query do
            field :a, :string do
              authorize :admin
            end
          end
        """)
      end

      assert_raise CompileError, ~r/invalid rule/, fn ->
        compile_schema("""
          query do
            field :a, :string do
              authorize any_of([])
            end
          end
        """)
      end
    end

    test "authorize twice on one definition fails" do
      assert_raise CompileError, ~r/declared twice/, fn ->
        compile_schema("""
          query do
            field :a, :string do
              authorize role(:admin)
              authorize role(:viewer)
            end
          end
        """)
      end
    end

    test "authorize in two sibling fields is fine" do
      mod =
        compile_schema("""
          query do
            field :a, :string do
              authorize role(:admin)
            end
            field :b, :string do
              authorize role(:viewer)
            end
          end
        """)

      assert Absinthe.Type.meta(Absinthe.Schema.lookup_type(mod, :query).fields.b, :warden_rule) ==
               {:role, :viewer}
    end

    test "authorize outside a field or type fails" do
      assert_raise CompileError, ~r/must be used inside/, fn ->
        compile_schema("""
          enum :e do
            authorize role(:admin)
            value :a
          end
          #{@query}
        """)
      end
    end

    test "an invalid list policy fails" do
      assert_raise CompileError, ~r/`list_policy` must be one of/, fn ->
        compile_schema("""
          query do
            field :a, list_of(:string) do
              list_policy :drop
            end
          end
        """)
      end
    end

    test "authorize_args on an input object field fails" do
      assert_raise CompileError,
                   ~r/`authorize_args` is not supported on input object fields/,
                   fn ->
                     compile_schema("""
                       input_object :i do
                         field :x, :string do
                           authorize_args x: role(:admin)
                         end
                       end
                       query do
                         field :a, :string do
                           arg :i, :i
                         end
                       end
                     """)
                   end
    end

    test "use Warden.Schema before use Absinthe.Schema fails" do
      assert_raise CompileError, ~r/must come after `use Absinthe.Schema`/, fn ->
        compile!("""
        defmodule #{unique("Warden.Test.Compiled.Order")} do
          use Warden.Schema, authorizer: Warden.Test.Authz
          use Absinthe.Schema
          #{@query}
        end
        """)
      end
    end

    test "invalid schema options fail" do
      assert_raise CompileError, ~r/`:strict_mode` must be false, :root or :all/, fn ->
        compile_schema(@query, "authorizer: Warden.Test.Authz, strict_mode: true")
      end

      assert_raise CompileError, ~r/`:authorizer` is required/, fn ->
        compile_schema(@query, "strict_mode: false")
      end

      assert_raise CompileError, ~r/`:default_object_rule`: role :nobody/, fn ->
        compile_schema(
          @query,
          "authorizer: Warden.Test.Authz, default_object_rule: role(:nobody)"
        )
      end
    end
  end

  describe "strict_mode" do
    @body """
      object :thing do
        field :x, :string
        field :y, :string do
          authorize public()
        end
      end

      interface :named do
        field :name, :string do
          authorize role(:viewer)
        end
        resolve_type fn _, _ -> :named_thing end
      end

      object :named_thing do
        interfaces [:named]
        field :name, :string
        field :z, :string
      end

      query do
        field :a, :string do
          authorize public()
        end
        field :b, :thing
        field :c, :named
        field :d, :named_thing
      end

      mutation do
        field :m, :string
      end
    """

    test "false (default) requires nothing" do
      assert compile_schema(@body)
    end

    test ":root names every root field without a rule" do
      error =
        assert_raise CompileError, fn ->
          compile_schema(@body, "authorizer: Warden.Test.Authz, strict_mode: :root")
        end

      message = Exception.message(error)
      assert message =~ "RootQueryType.b: no rule declared"
      assert message =~ "RootQueryType.c: no rule declared"
      assert message =~ "RootQueryType.d: no rule declared"
      assert message =~ "RootMutationType.m: no rule declared"
      refute message =~ "RootQueryType.a:"
      refute message =~ "Thing.x"
      refute message =~ "__schema"
    end

    test ":all also covers non-root object fields; introspection and interface rules excluded" do
      error =
        assert_raise CompileError, fn ->
          compile_schema(@body, "authorizer: Warden.Test.Authz, strict_mode: :all")
        end

      message = Exception.message(error)
      assert message =~ "Thing.x: no rule declared"
      assert message =~ "NamedThing.z: no rule declared"
      refute message =~ "Thing.y:"
      refute message =~ "NamedThing.name:"
      refute message =~ "__typename"
      refute message =~ "__Type"
    end

    test "a fully declared schema compiles under :all" do
      assert compile_schema(
               """
                 query do
                   field :a, :string do
                     authorize public()
                   end
                 end
               """,
               "authorizer: Warden.Test.Authz, strict_mode: :all"
             )
    end
  end

  describe "verifier" do
    defmodule Stripper do
      @moduledoc false
      # A user pipeline modifier that removes Warden's middleware after it was attached.
      def pipeline(pipeline) do
        Absinthe.Pipeline.insert_before(pipeline, Absinthe.Phase.Schema.Compile, __MODULE__.Phase)
      end

      defmodule Phase do
        @moduledoc false
        use Absinthe.Phase

        def run(bp, _) do
          [sd] = bp.schema_definitions

          artifacts =
            Enum.map(sd.type_artifacts, fn
              %{fields: fields} = type when is_map(fields) ->
                fields =
                  Map.new(fields, fn {k, f} ->
                    {k,
                     %{
                       f
                       | middleware: Enum.reject(f.middleware, &Warden.Middleware.warden_entry?/1)
                     }}
                  end)

                %{type | fields: fields}

              type ->
                type
            end)

          {:ok, %{bp | schema_definitions: [%{sd | type_artifacts: artifacts}]}}
        end
      end
    end

    test "a pipeline modifier that strips Warden middleware fails compilation" do
      error =
        assert_raise CompileError, fn ->
          compile_schema("""
            @pipeline_modifier Warden.CompileTest.Stripper
            query do
              field :a, :string do
                authorize role(:admin)
              end
            end
          """)
        end

      assert Exception.message(error) =~
               "RootQueryType.a: pre middleware absent, plan requires present"
    end

    test "verify/1 passes on the test schema" do
      assert Warden.Verifier.verify(Warden.Test.Schema) == :ok
    end
  end

  describe "authorizer options" do
    defp compile_authorizer(opts, body \\ "") do
      compile!("""
      defmodule #{unique("Warden.Test.Compiled.Authz")} do
        use Warden.Authorizer, #{opts}
        def subject(c), do: c[:user]
        def roles(u, _), do: u.roles
        #{body}
      end
      """)
    end

    test "a cyclic hierarchy fails" do
      assert_raise CompileError, ~r/`:role_hierarchy` has a cycle: :a -> :b -> :a/, fn ->
        compile_authorizer("roles: [:a, :b], role_hierarchy: %{a: [:b], b: [:a]}")
      end

      assert_raise CompileError, ~r/has a cycle/, fn ->
        compile_authorizer("roles: [:a], role_hierarchy: %{a: [:a]}")
      end
    end

    test "unknown roles in the hierarchy fail" do
      assert_raise CompileError, ~r/implies :z, which is not a catalog role/, fn ->
        compile_authorizer("roles: [:a], role_hierarchy: %{a: [:z]}")
      end
    end

    test "role_permissions must use catalog roles and permissions" do
      assert_raise CompileError, ~r/names "x:y", which is not in the permission catalog/, fn ->
        compile_authorizer(~s|roles: [:a], permissions: ["p"], role_permissions: %{a: ["x:y"]}|)
      end

      assert_raise CompileError, ~r/key :ghost is not a catalog role/, fn ->
        compile_authorizer(~s|roles: [:a], role_permissions: %{ghost: :all}|)
      end
    end

    test "roles are required" do
      assert_raise CompileError, ~r/`:roles` is required/, fn ->
        compile_authorizer("checks: []")
      end
    end

    test "declared checks require check/2" do
      assert_raise CompileError, ~r/declares checks \[:self\] but does not define check\/2/, fn ->
        compile_authorizer("roles: [:a], checks: [:self]")
      end

      assert compile_authorizer("roles: [:a], checks: [:self]", "def check(:self, _), do: true")
    end

    test "unknown options fail" do
      assert_raise CompileError, ~r/unknown options: \[:rolez\]/, fn ->
        compile_authorizer("roles: [:a], rolez: []")
      end
    end
  end
end
