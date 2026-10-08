defmodule Warden.RedteamExec.DeeperTest do
  # Red-team, second pass: follow-ups on fragile spots found in the first pass.
  use ExUnit.Case, async: false

  import Warden.RedteamExec.Helpers
  import Warden.Test.CompileHelpers

  alias Warden.RedteamExec.Data

  defp viewer, do: Data.user(:viewer, id: "v1")

  defmodule Store do
    @moduledoc false
    def set_role(_, args, %{context: c}) do
      send(c.test_pid, {:set_role, args})
      {:ok, true}
    end
  end

  @mutation_schema """
  query do
    field :x, :string
  end

  input_object :profile do
    field :name, :string
    field :role, :string do
      authorize role(:admin)
    end
  end

  mutation do
    field :set_role, :boolean do
      arg :user_id, :id
      arg :role, :string
      authorize_args role: role(:admin)
      resolve &Warden.RedteamExec.DeeperTest.Store.set_role/3
    end

    field :update_profile, :boolean do
      arg :profile, :profile
      resolve &Warden.RedteamExec.DeeperTest.Store.set_role/3
    end
  end
  """

  describe "explicit null for a restricted argument without a default" do
    test "role: null (clearing a guarded value) is a write the rule must cover" do
      schema = compile_schema(@mutation_schema, "authorizer: Warden.RedteamExec.Authz")
      run(~s|mutation { setRole(userId: "u9", role: null) }|, viewer(), schema: schema)
      # The resolver sees %{role: nil} (key present) and would clear the role.
      refute_received {:set_role, %{role: nil}}
    end

    test "an input field set to null explicitly is covered by its input-field rule" do
      schema = compile_schema(@mutation_schema, "authorizer: Warden.RedteamExec.Authz")

      run(~s|mutation { updateProfile(profile: {name: "x", role: null}) }|, viewer(),
        schema: schema
      )

      refute_received {:set_role, %{profile: %{role: nil}}}
    end

    test "a variable explicitly set to null for a guarded argument" do
      schema = compile_schema(@mutation_schema, "authorizer: Warden.RedteamExec.Authz")

      run(~s|mutation($r: String) { setRole(userId: "u9", role: $r) }|, viewer(),
        schema: schema,
        variables: %{"r" => nil}
      )

      refute_received {:set_role, %{role: nil}}
    end
  end

  describe "introspection reached through a nested root object" do
    test "a mutation payload exposing the query root keeps the introspection guard" do
      schema =
        compile_schema(
          """
          query do
            field :x, :string
          end

          object :payload do
            field :query, :query do
              resolve fn _, _, _ -> {:ok, %{}} end
            end
          end

          mutation do
            field :touch, :payload do
              resolve fn _, _, _ -> {:ok, %{}} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz, introspection: role(:admin)"
        )

      result =
        run("mutation { touch { query { __schema { queryType { name } } } } }", viewer(),
          schema: schema
        )

      refute contains?(result, "RootQueryType")
    end
  end

  describe "query root object rule reached through a nested field" do
    test "a field returning the query root type applies the root type rule" do
      schema =
        compile_schema(
          """
          query do
            authorize role(:admin)
            field :secret, :string do
              resolve fn _, _, _ -> {:ok, "root-secret"} end
            end
          end

          object :payload do
            field :query, :query do
              resolve fn _, _, _ -> {:ok, %{}} end
            end
          end

          mutation do
            field :touch, :payload do
              resolve fn _, _, _ -> {:ok, %{}} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )

      result = run("mutation { touch { query { secret } } }", viewer(), schema: schema)
      refute contains?(result, "root-secret")
    end
  end
end
