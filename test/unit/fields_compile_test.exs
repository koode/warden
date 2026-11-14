defmodule Warden.FieldsCompileTest do
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers

  alias Warden.Authorizer.Catalog
  alias Warden.Test.Fields.{Authz, CommentFields}

  @options "authorizer: Warden.Test.Fields.Authz, for: Warden.Test.Fields.Comment"

  defp fields_module(body, opts) do
    name = unique("Warden.Test.Compiled.F")

    compile!("""
    defmodule #{name} do
      use Warden.Fields, #{opts}
    #{body}
    end
    """)
  end

  defp compile_error(body, opts) do
    error = assert_raise CompileError, fn -> fields_module(body, opts) end
    Exception.message(error)
  end

  defp compile_error(body), do: compile_error(body, @options)

  test "the authorizer lists its field policies and the policy names its struct" do
    assert CommentFields in Authz.__warden_catalog__().fields
    assert Warden.Fields.fields_for(Authz, Warden.Test.Fields.Comment) == CommentFields
    assert Warden.Fields.fields_for(Authz, %Warden.Test.Fields.Comment{}) == CommentFields
    assert Warden.Fields.fields_for(Authz, Warden.Test.Fields.Tag) == nil

    %{for: Warden.Test.Fields.Comment, redactions: redactions} =
      CommentFields.__warden_fields__(:info)

    assert Enum.map(redactions, & &1.field) == [:body, :anchor, :author_id]
  end

  test "a field policy its authorizer does not list fails compilation" do
    assert compile_error(~s|redact :body, with: "", unless: check(:live)|) =~
             "does not list"
  end

  describe "with a listing authorizer" do
    # The compile-time checks after the listing check; the module names below are listed
    # by `Warden.Test.Fields.OpenAuthz`.
    defp listed(name, body, struct \\ "Warden.Test.Fields.Comment") do
      compile!("""
      defmodule #{name} do
        use Warden.Fields, authorizer: Warden.Test.Fields.OpenAuthz, for: #{struct}
      #{body}
      end
      """)
    end

    defp listed_error(name, body, struct \\ "Warden.Test.Fields.Comment") do
      error = assert_raise CompileError, fn -> listed(name, body, struct) end
      Exception.message(error)
    end

    test "an unknown field fails compilation" do
      assert listed_error(
               "Warden.Test.Fields.Open1",
               ~s|redact :bdy, with: "", unless: check(:live)|
             ) =~
               ":bdy, which is not a field of Warden.Test.Fields.Comment"
    end

    test "a field named twice fails compilation" do
      body = """
      redact :body, with: "", unless: check(:live)
      redact :body, with: "x", unless: role(:staff)
      """

      assert listed_error("Warden.Test.Fields.Open2", body) =~ "names :body twice"
    end

    test "a rule outside the catalog fails compilation" do
      assert listed_error(
               "Warden.Test.Fields.Open3",
               ~s|redact :body, with: "", unless: role(:nope)|
             ) =~
               "invalid `unless:` rule for :body"

      assert listed_error(
               "Warden.Test.Fields.Open4",
               ~s|redact :body, with: "", unless: check(:nope)|
             ) =~
               "check(:nope)"
    end

    test "covered() and rules that read field arguments fail compilation" do
      assert listed_error(
               "Warden.Test.Fields.Open5",
               ~s|redact :body, with: "", unless: covered()|
             ) =~
               "covered()"

      body = ~s|redact :body, with: "", unless: tenant_role(:member, tenant: {:arg, [:id]})|
      assert listed_error("Warden.Test.Fields.Open6", body) =~ "cannot read field arguments"

      body =
        ~s|redact :body, with: "", unless: any_of([role(:staff), can(Warden.Test.Fields.Comments, :read, arg: [:id])])|

      assert listed_error("Warden.Test.Fields.Open7", body) =~ "can(Warden.Test.Fields.Comments"
    end

    test "redact takes exactly with: and unless:" do
      assert listed_error("Warden.Test.Fields.Open8", ~s|redact :body, unless: check(:live)|) =~
               "takes exactly `with:` and `unless:`"

      assert listed_error(
               "Warden.Test.Fields.Open9",
               ~s|redact :body, with: "", unless: check(:live), also: 1|
             ) =~
               "takes exactly `with:` and `unless:`"
    end

    test "a for: module that is not a struct fails compilation" do
      assert listed_error("Warden.Test.Fields.Open10", "", "Enum") =~ "is not a struct module"
    end

    test "a valid field policy compiles" do
      body = ~s|redact :body, with: "", unless: any_of([check(:live), kind(:webhook)])|
      [{module, _binary}] = listed("Warden.Test.Fields.Open11", body)
      assert %{redactions: [%{field: :body, with: ""}]} = module.__warden_fields__(:info)
    end
  end

  test "unknown options and a missing authorizer fail compilation" do
    assert compile_error(
             "",
             "authorizer: Warden.Test.Fields.Authz, for: Warden.Test.Fields.Comment, extra: 1"
           ) =~
             "unknown options: [:extra]"

    assert compile_error("", "for: Warden.Test.Fields.Comment") =~
             "`:authorizer` (a module) is required"

    assert compile_error("", "authorizer: Enum, for: Warden.Test.Fields.Comment") =~
             "does not `use Warden.Authorizer`"
  end

  test "the authorizer validates its fields: option" do
    assert {:error, [message]} = Catalog.build(roles: [:a], fields: [Foo, Foo])
    assert message =~ "duplicates"
    assert {:error, [_message]} = Catalog.build(roles: [:a], fields: "Foo")
  end
end
