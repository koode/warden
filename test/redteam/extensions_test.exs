defmodule Warden.Redteam.ExtensionsTest do
  @moduledoc """
  Red team, schema-shape lens: type extensions and declaration order that change which
  interfaces or rules a type has after it is first defined.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers
  import Warden.Test.CompileHelpers

  @authz "authorizer: Warden.Redteam.Authz"

  test "an interface added to an object with extend object brings its object rule" do
    body = """
    interface :classified do
      authorize role(:admin)
      field :id, :id
      resolve_type fn _, _ -> :report end
    end

    object :report do
      field :id, :id
      field :body, :string
    end

    extend object(:report) do
      interfaces [:classified]
    end

    query do
      field :report, :report, resolve: fn _, _ -> {:ok, %{id: "r", body: "BODY"}} end
    end
    """

    schema = compile_schema(body, @authz)
    r = run(~s|{ report { body } }|, viewer(), schema: schema)
    assert r.data == %{"report" => nil}
  end

  test "an interface field rule applies to a field the object gets through extend object" do
    body = """
    interface :classified do
      field :code, :string do
        authorize role(:admin)
      end
      resolve_type fn _, _ -> :report end
    end

    object :report do
      interfaces [:classified]
      field :id, :id
    end

    extend object(:report) do
      field :code, :string
    end

    query do
      field :report, :report, resolve: fn _, _ -> {:ok, %{id: "r", code: "CODE"}} end
    end
    """

    schema = compile_schema(body, @authz)
    r = run(~s|{ report { code } }|, viewer(), schema: schema)
    assert r.data == %{"report" => %{"code" => nil}}
  end

  test "an interface field rule added with extend interface applies to implementors" do
    body = """
    interface :classified do
      field :id, :id
      resolve_type fn _, _ -> :report end
    end

    extend interface(:classified) do
      field :code, :string do
        authorize role(:admin)
      end

      resolve_type fn _, _ -> :report end
    end

    object :report do
      interfaces [:classified]
      field :id, :id
      field :code, :string
    end

    query do
      field :c, :classified, resolve: fn _, _ -> {:ok, %{id: "r", code: "CODE"}} end
    end
    """

    schema = compile_schema(body, @authz)
    r = run(~s|{ c { ... on Report { code } } }|, viewer(), schema: schema)
    assert r.data == %{"c" => %{"code" => nil}}
  end

  test "authorize declared last, after arguments and the resolver, still attaches to the field" do
    body = """
    query do
      field :x, :string do
        arg :a, :string, description: "an arg"
        resolve fn _, _ -> {:ok, "X-SECRET"} end
        authorize role(:admin)
      end
    end
    """

    schema = compile_schema(body, @authz)
    assert run(~s|{ x(a: "1") }|, viewer(), schema: schema).data == %{"x" => nil}
  end

  test "a union member added with extend union is checked through the union" do
    body = """
    object :vault do
      authorize role(:admin)
      field :code, :string
    end

    object :open do
      field :label, :string
    end

    union :anything do
      types [:open]
      resolve_type fn %{kind: k}, _ -> k end
    end

    extend union(:anything) do
      types [:vault]
      resolve_type fn %{kind: k}, _ -> k end
    end

    query do
      field :any, list_of(:anything) do
        resolve fn _, _ -> {:ok, [%{kind: :open, label: "o"}, %{kind: :vault, code: "ALPHA"}]} end
      end
    end
    """

    schema =
      try do
        compile_schema(body, @authz)
      rescue
        # Absinthe may not support extending union members; nothing to attack then.
        _ in [CompileError, Absinthe.Schema.Error] -> nil
      end

    assert schema, "extend union did not compile"

    if schema do
      r = run(~s|{ any { __typename ... on Vault { code } } }|, viewer(), schema: schema)
      refute contains?(r.data, "ALPHA")
      refute contains?(r.data, "Vault")
    end
  end
end
