defmodule Warden.Integration.HydrateTest do
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  defmodule SDLSchema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Schema, authorizer: Warden.Test.Authz

    import_sdl """
    type Query {
      secret: Secret
      salary(raw: Boolean = false): String
      open: String
    }

    type Secret {
      code: String
    }
    """

    alias Absinthe.Blueprint.Schema.{FieldDefinition, ObjectTypeDefinition}

    def hydrate(%ObjectTypeDefinition{identifier: :secret}, _) do
      [Warden.Hydrate.meta([rule: role(:admin)], cache: false)]
    end

    def hydrate(%FieldDefinition{identifier: :secret}, [
          %ObjectTypeDefinition{identifier: :query} | _
        ]) do
      [{:resolve, &__MODULE__.secret/2}]
    end

    def hydrate(%FieldDefinition{identifier: :salary}, [
          %ObjectTypeDefinition{identifier: :query} | _
        ]) do
      [
        {:resolve, &__MODULE__.salary/2},
        Warden.Hydrate.meta(rule: authenticated(), args: [raw: role(:admin)])
      ]
    end

    def hydrate(%FieldDefinition{identifier: :open}, [
          %ObjectTypeDefinition{identifier: :query} | _
        ]) do
      [{:resolve, &__MODULE__.open/2}]
    end

    def hydrate(_, _), do: []

    def secret(_, _), do: {:ok, %{code: "ALPHA"}}
    def salary(_, _), do: {:ok, "1000"}
    def open(_, _), do: {:ok, "open"}
  end

  test "object rules declared through hydrate apply" do
    assert run("{ secret { code } }", viewer(), schema: SDLSchema).data == %{"secret" => nil}

    assert run("{ secret { code } }", admin(), schema: SDLSchema).data ==
             %{"secret" => %{"code" => "ALPHA"}}
  end

  test "extra meta passed to Warden.Hydrate.meta is kept" do
    assert Absinthe.Type.meta(Absinthe.Schema.lookup_type(SDLSchema, :secret), :cache) == false
  end

  test "field and argument rules declared through hydrate apply" do
    assert run("{ salary }", nil, schema: SDLSchema).data == %{"salary" => nil}
    assert run("{ salary }", viewer(), schema: SDLSchema).data == %{"salary" => "1000"}
    assert run("{ salary(raw: true) }", viewer(), schema: SDLSchema).data == %{"salary" => nil}
    assert run("{ salary(raw: true) }", admin(), schema: SDLSchema).data == %{"salary" => "1000"}
  end

  test "Warden.Hydrate.meta validates its input" do
    assert_raise ArgumentError, ~r/invalid rule rule/, fn -> Warden.Hydrate.meta(rule: :admin) end

    assert_raise ArgumentError, ~r/invalid list policy/, fn ->
      Warden.Hydrate.meta(list_policy: :x)
    end

    assert_raise ArgumentError, ~r/unknown/, fn -> Warden.Hydrate.meta(nope: 1) end
  end

  test "hydrated rules are checked against the catalog at compile time" do
    assert_raise CompileError, ~r/role :ghost is not in the authorizer's role catalog/, fn ->
      Warden.Test.CompileHelpers.compile!("""
      defmodule #{Warden.Test.CompileHelpers.unique("Warden.Test.Compiled.SDL")} do
        use Absinthe.Schema
        use Warden.Schema, authorizer: Warden.Test.Authz

        import_sdl "type Query { a: String }"

        def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :a}, _),
          do: [Warden.Hydrate.meta(rule: role(:ghost))]

        def hydrate(_, _), do: []
      end
      """)
    end
  end
end
