defmodule Warden.Redteam.SchemaConstructionTest do
  @moduledoc """
  Red team, schema-shape lens: names that collide with root or introspection names,
  identifiers vs names, strict mode, import_fields, macros, SDL + hydrate and
  declaration order. Each schema is compiled in the test.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers
  import Warden.Test.CompileHelpers

  @authz "authorizer: Warden.Redteam.Authz"

  defp strict_error(body, mode) do
    try do
      compile_schema(body, @authz <> ", strict_mode: #{inspect(mode)}")
      :compiled
    rescue
      e in CompileError -> {:error, Exception.message(e)}
    end
  end

  describe "introspection guard" do
    @named_query """
    object :meta_info, name: "Query" do
      field :label, :string
    end

    query do
      field :meta, :meta_info do
        resolve fn _, _ -> {:ok, %{label: "m"}} end
      end

      field :ping, :string, resolve: fn _, _ -> {:ok, "pong"} end
    end
    """

    test "control: __schema on the root follows the introspection rule" do
      schema = compile_schema(@named_query, @authz <> ", introspection: role(:admin)")
      r = run(~s|{ __schema { queryType { name } } }|, viewer(), schema: schema)
      assert r.data == %{"__schema" => nil}
    end

    test "__schema on a non-root object named Query escapes the introspection rule" do
      schema = compile_schema(@named_query, @authz <> ", introspection: role(:admin)")
      r = run(~s|{ meta { __schema { types { name } } } }|, viewer(), schema: schema)
      refute contains?(Map.get(r, :data), "RootQueryType")
    end

    test "__type on a non-root object named Query escapes the introspection rule" do
      schema = compile_schema(@named_query, @authz <> ", introspection: role(:admin)")

      r =
        run(~s|{ meta { __type(name: "RootQueryType") { name fields { name } } } }|, viewer(),
          schema: schema
        )

      refute contains?(Map.get(r, :data), "ping")
    end

    test "SDL: __schema on a non-root SDL type named RootQueryType escapes the introspection rule" do
      body = ~S'''
      import_sdl """
      schema { query: Root }
      type Root { meta: RootQueryType }
      type RootQueryType { label: String }
      """

      def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :meta}, _) do
        {:resolve, &__MODULE__.resolve_meta/3}
      end

      def resolve_meta(_, _, _), do: {:ok, %{label: "m"}}

      def hydrate(_, _), do: []
      '''

      schema = compile_schema(body, @authz <> ", introspection: role(:admin)")
      r = run(~s|{ meta { __schema { types { name } } } }|, viewer(), schema: schema)
      refute contains?(Map.get(r, :data), "Root")
    end

    test "introspection selected under an alias in a fragment on the root" do
      schema = compile_schema(@named_query, @authz <> ", introspection: role(:admin)")

      doc = """
      { ...F }
      fragment F on RootQueryType { s: __schema { types { name } } t: __type(name: "Query") { name } }
      """

      r = run(doc, viewer(), schema: schema)
      assert r.data == %{"s" => nil, "t" => nil}
    end

    test "introspection on the mutation root is not available as a back door" do
      body = """
      query do
        field :ping, :string, resolve: fn _, _ -> {:ok, "pong"} end
      end

      mutation do
        field :noop, :boolean, resolve: fn _, _ -> {:ok, true} end
      end
      """

      schema = compile_schema(body, @authz <> ", introspection: role(:admin)")
      r = run(~s|mutation { __schema { types { name } } }|, viewer(), schema: schema)
      refute contains?(Map.get(r, :data), "RootQueryType")
    end
  end

  describe "identifiers that look like introspection" do
    @dunder """
    object :secret do
      authorize role(:admin)
      field :code, :string
    end

    query do
      field :__internal, :string, name: "internal" do
        authorize role(:admin)
        resolve fn _, _ -> {:ok, "INTERNAL-SECRET"} end
      end

      field :__secret, :secret, name: "secret_thing" do
        resolve fn _, _ -> {:ok, %{code: "ALPHA"}} end
      end
    end
    """

    test "a field rule on a field whose identifier starts with __ is enforced" do
      schema = compile_schema(@dunder, @authz)
      r = run(~s|{ internal }|, viewer(), schema: schema)
      refute contains?(r.data, "INTERNAL-SECRET")
    end

    test "an object rule on the return type of a field whose identifier starts with __ is enforced" do
      schema = compile_schema(@dunder, @authz)
      r = run(~s|{ secretThing { __typename } }|, viewer(), schema: schema)
      assert r.data == %{"secretThing" => nil}
    end

    test "strict_mode :root names a root field whose identifier starts with __" do
      body = """
      query do
        field :__internal, :string, name: "internal" do
          resolve fn _, _ -> {:ok, "x"} end
        end
      end
      """

      assert {:error, msg} = strict_error(body, :root)
      assert msg =~ "internal"
    end

    test "strict_mode :all names an object field whose identifier starts with __" do
      body = """
      object :thing do
        field :__hidden, :string, name: "hidden"
      end

      query do
        field :thing, :thing do
          authorize public()
          resolve fn _, _ -> {:ok, %{}} end
        end
      end
      """

      assert {:error, msg} = strict_error(body, :all)
      assert msg =~ "hidden"
    end
  end

  describe "root types" do
    @root_rule """
    query do
      authorize authenticated()
      field :ping, :string, resolve: fn _, _ -> {:ok, "pong"} end
    end
    """

    test "control: a root object rule denies root fields to anonymous" do
      schema = compile_schema(@root_rule, @authz)
      assert run(~s|{ ping }|, nil, schema: schema).data == %{"ping" => nil}
    end

    test "a root object rule also hides __typename of the root" do
      schema = compile_schema(@root_rule, @authz)
      r = run(~s|{ __typename }|, nil, schema: schema)
      refute contains?(Map.get(r, :data), "RootQueryType")
    end

    test "a root object rule also applies to __schema" do
      schema = compile_schema(@root_rule, @authz)
      r = run(~s|{ __schema { types { name } } }|, nil, schema: schema)
      refute contains?(Map.get(r, :data), "RootQueryType")
    end

    test "a root object rule applies when the root type is reached through a nested field" do
      body = """
      object :payload do
        field :query, :query, resolve: fn _, _, _ -> {:ok, %{}} end
      end

      query do
        authorize role(:admin)
        field :ping, :string, resolve: fn _, _ -> {:ok, "pong"} end
      end

      mutation do
        field :touch, :payload, resolve: fn _, _ -> {:ok, %{}} end
      end
      """

      schema = compile_schema(body, @authz)
      r = run(~s|mutation { touch { query { ping } } }|, viewer(), schema: schema)
      refute contains?(Map.get(r, :data), "pong")
    end

    test "strict_mode :root names a root field added with extend object" do
      body = """
      query do
        field :ping, :string do
          authorize public()
          resolve fn _, _ -> {:ok, "pong"} end
        end
      end

      extend object(:query) do
        field :leak, :string, resolve: fn _, _, _ -> {:ok, "x"} end
      end
      """

      assert {:error, msg} = strict_error(body, :root)
      assert msg =~ "leak"
    end

    test "strict_mode :root names a root field pulled in with import_fields" do
      body = """
      object :extra_root_fields do
        field :leak, :string, resolve: fn _, _, _ -> {:ok, "x"} end
      end

      query do
        import_fields :extra_root_fields
      end
      """

      assert {:error, msg} = strict_error(body, :root)
      assert msg =~ "leak"
    end

    test "strict_mode :root names a mutation and a subscription field" do
      body = """
      query do
        field :ping, :string do
          authorize public()
          resolve fn _, _ -> {:ok, "pong"} end
        end
      end

      mutation do
        field :m_leak, :boolean, resolve: fn _, _ -> {:ok, true} end
      end

      subscription do
        field :s_leak, :string do
          config fn _, _ -> {:ok, topic: "x"} end
        end
      end
      """

      assert {:error, msg} = strict_error(body, :root)
      assert msg =~ "mLeak" or msg =~ "m_leak"
      assert msg =~ "sLeak" or msg =~ "s_leak"
    end
  end

  describe "schema building" do
    test "interface declared after its implementors still merges its rules" do
      body = """
      object :doc do
        interfaces [:late]
        field :id, :id
        field :note, :string
      end

      interface :late do
        authorize authenticated()
        field :id, :id
        field :note, :string do
          authorize role(:admin)
        end
        resolve_type fn _, _ -> :doc end
      end

      query do
        field :doc, :doc, resolve: fn _, _ -> {:ok, %{id: "d", note: "NOTE"}} end
      end
      """

      schema = compile_schema(body, @authz)

      assert run(~s|{ doc { note } }|, viewer(), schema: schema).data == %{
               "doc" => %{"note" => nil}
             }

      assert run(~s|{ doc { id } }|, nil, schema: schema).data == %{"doc" => nil}
    end

    test "import_fields from an interface keeps field and argument rules and list policy" do
      body = """
      object :item do
        authorize role(:admin)
        field :id, :id
      end

      interface :listing do
        field :items, list_of(:item) do
          arg :all, :boolean, default_value: false
          authorize_args all: role(:admin)
          list_policy :filter
        end

        field :note, :string do
          authorize role(:admin)
        end

        resolve_type fn _, _ -> :shelf end
      end

      object :shelf do
        interfaces [:listing]
        import_fields :listing
      end

      query do
        field :shelf, :shelf, resolve: fn _, _ -> {:ok, %{items: [%{id: "i1"}], note: "NOTE"}} end
      end
      """

      schema = compile_schema(body, @authz)
      r = run(~s|{ shelf { note items { id } } }|, viewer(), schema: schema)
      assert r.data == %{"shelf" => %{"note" => nil, "items" => []}}
      r = run(~s|{ shelf { items(all: true) { id } } }|, viewer(), schema: schema)
      assert r.data == %{"shelf" => %{"items" => nil}}
    end

    test "fields generated by a macro keep their rules" do
      mac = unique("Warden.Test.Compiled.Mac")

      compile!("""
      defmodule #{mac} do
        defmacro guarded_field(name, value) do
          quote do
            field unquote(name), :string do
              authorize role(:admin)
              resolve fn _, _, _ -> {:ok, unquote(value)} end
            end
          end
        end
      end
      """)

      body = """
      require #{mac}
      import #{mac}

      query do
        guarded_field :one, "SECRET-ONE"
        guarded_field :two, "SECRET-TWO"
        field :open, :string, resolve: fn _, _ -> {:ok, "open"} end
      end
      """

      schema = compile_schema(body, @authz)
      r = run(~s|{ one two open }|, viewer(), schema: schema)
      assert r.data == %{"one" => nil, "two" => nil, "open" => "open"}
    end

    test "authorize placed after a sub-field definition inside an object stays an object rule" do
      body = """
      object :vault do
        field :code, :string
        authorize role(:admin)
      end

      query do
        field :vault, :vault, resolve: fn _, _ -> {:ok, %{code: "ALPHA"}} end
      end
      """

      schema = compile_schema(body, @authz)
      assert run(~s|{ vault { __typename } }|, viewer(), schema: schema).data == %{"vault" => nil}
    end

    test "SDL + hydrate: interface object rule, union rule and interface field rule" do
      body = ~S'''
      import_sdl """
      interface Classified { id: ID! note: String }
      type File implements Classified { id: ID! note: String name: String }
      type Memo { text: String }
      union Pile = File | Memo
      type Query { file: Classified piles: [Pile] }
      """

      def hydrate(%Absinthe.Blueprint.Schema.InterfaceTypeDefinition{identifier: :classified}, _) do
        [Warden.Absinthe.Hydrate.meta(rule: role(:editor)), {:resolve_type, &__MODULE__.file_type/2}]
      end

      def hydrate(%Absinthe.Blueprint.Schema.UnionTypeDefinition{identifier: :pile}, _) do
        [
          Warden.Absinthe.Hydrate.meta(rule: role(:admin)),
          {:resolve_type, &__MODULE__.pile_type/2}
        ]
      end

      def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :note}, [
            %Absinthe.Blueprint.Schema.InterfaceTypeDefinition{} | _
          ]) do
        Warden.Absinthe.Hydrate.meta(rule: role(:admin))
      end

      def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :file}, _) do
        {:resolve, &__MODULE__.resolve_file/3}
      end

      def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :piles}, _) do
        {:resolve, &__MODULE__.resolve_piles/3}
      end

      def hydrate(_, _), do: []

      def file_type(_, _), do: :file
      def pile_type(v, _), do: if(Map.has_key?(v, :text), do: :memo, else: :file)
      def resolve_file(_, _, _), do: {:ok, %{id: "f", note: "NOTE", name: "FILE-NAME"}}
      def resolve_piles(_, _, _), do: {:ok, [%{text: "MEMO"}, %{id: "f", note: "N", name: "FILE-NAME"}]}
      '''

      schema = compile_schema(body, @authz)
      # File reached through the interface: the interface object rule (editor) applies.
      assert run(~s|{ file { id } }|, viewer(), schema: schema).data == %{"file" => nil}
      # Editor passes the object rule but the interface field rule (admin) applies.
      assert run(~s|{ file { note ... on File { name } } }|, editor(), schema: schema).data ==
               %{"file" => %{"note" => nil, "name" => "FILE-NAME"}}

      # The union rule (admin) applies to every member.
      r = run(~s|{ piles { __typename } }|, editor(), schema: schema)
      assert r.data == %{"piles" => [nil, nil]}
    end

    test "default_object_rule applies to implementors reached through an interface" do
      body = """
      interface :thing do
        field :id, :id
        resolve_type fn _, _ -> :box end
      end

      object :box do
        interfaces [:thing]
        field :id, :id
      end

      query do
        field :thing, :thing, resolve: fn _, _ -> {:ok, %{id: "b"}} end
      end
      """

      schema = compile_schema(body, @authz <> ", default_object_rule: authenticated()")
      assert run(~s|{ thing { id __typename } }|, nil, schema: schema).data == %{"thing" => nil}
    end
  end
end
