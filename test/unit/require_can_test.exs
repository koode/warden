defmodule Warden.Absinthe.RequireCanTest do
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers

  @opts "authorizer: Warden.Test.Ecto.Authz, strict_mode: :all, require_can_for: [Warden.Test.Ecto.Issue]"

  defp schema!(object, opts \\ @opts) do
    compile_schema(
      """
      #{object}

      query do
        field :issue, :issue do
          authorize public()
          resolve fn _args, _resolution -> {:ok, nil} end
        end
      end
      """,
      opts
    )
  end

  test "an object type linked to a listed schema must use can/2 with its policy" do
    assert_raise CompileError,
                 ~r/Issue: its values are Warden.Test.Ecto.Issue .* must use can\/2/,
                 fn ->
                   schema!("""
                   object :issue do
                     warden_schema Warden.Test.Ecto.Issue
                     authorize authenticated()
                     field :id, :id, do: authorize(covered())
                   end
                   """)
                 end
  end

  test "can/2 with the schema's policy passes, also inside any_of" do
    for rule <- [
          "can(Warden.Test.Ecto.Issues, :read)",
          "any_of([role(:instance_admin), can(Warden.Test.Ecto.Issues, :read)])"
        ] do
      assert schema!("""
             object :issue do
               warden_schema Warden.Test.Ecto.Issue
               authorize #{rule}
               field :id, :id, do: authorize(covered())
             end
             """)
    end
  end

  test "can/2 with another schema's policy does not count" do
    assert_raise CompileError, ~r/must use can\/2 with Warden.Test.Ecto.Issue's policy/, fn ->
      schema!("""
      object :issue do
        warden_schema Warden.Test.Ecto.Issue
        authorize can(Warden.Test.Ecto.Teams, :read)
        field :id, :id, do: authorize(covered())
      end
      """)
    end
  end

  test "a listed schema that no object type is linked to fails" do
    assert_raise CompileError,
                 ~r/`require_can_for` lists Warden.Test.Ecto.Issue, but no object type/,
                 fn ->
                   schema!("""
                   object :issue do
                     authorize authenticated()
                     field :id, :id, do: authorize(covered())
                   end
                   """)
                 end
  end

  test "the option needs strict_mode: :all and modules" do
    assert_raise CompileError, ~r/`:require_can_for` needs `strict_mode: :all`/, fn ->
      schema!(
        "object :issue do\n  field :id, :id\nend",
        "authorizer: Warden.Test.Ecto.Authz, require_can_for: [Warden.Test.Ecto.Issue]"
      )
    end

    assert_raise CompileError, ~r/`:require_can_for` must be a list of modules/, fn ->
      schema!(
        "object :issue do\n  field :id, :id\nend",
        "authorizer: Warden.Test.Ecto.Authz, strict_mode: :all, require_can_for: \"issues\""
      )
    end
  end

  test "warden_schema needs a module and belongs inside an object" do
    assert_raise CompileError, ~r/`warden_schema` needs a module/, fn ->
      schema!("""
      object :issue do
        warden_schema "issues"
        authorize can(Warden.Test.Ecto.Issues, :read)
        field :id, :id, do: authorize(covered())
      end
      """)
    end

    assert_raise CompileError, ~r/`warden_schema` must be used inside `object`/, fn ->
      schema!("""
      object :issue do
        authorize can(Warden.Test.Ecto.Issues, :read)
        field :id, :id do
          warden_schema Warden.Test.Ecto.Issue
          authorize covered()
        end
      end
      """)
    end
  end

  test "warden_schema is stored as :warden_schema meta" do
    schema =
      schema!("""
      object :issue do
        warden_schema Warden.Test.Ecto.Issue
        authorize can(Warden.Test.Ecto.Issues, :read)
        field :id, :id, do: authorize(covered())
      end
      """)

    assert schema |> Absinthe.Schema.lookup_type(:issue) |> Absinthe.Type.meta(:warden_schema) ==
             Warden.Test.Ecto.Issue
  end
end
