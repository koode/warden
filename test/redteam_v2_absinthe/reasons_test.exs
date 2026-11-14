defmodule Warden.RedteamV2Absinthe.ReasonsTest do
  # Reasons, traces and tenant roles in GraphQL responses. All defended.
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers
  import Warden.Test.RedteamV2.People

  @exposing_schema """
    query do
      field :quota, :string do
        authorize check(:reasoned)
        resolve fn _args, _resolution -> {:ok, "quota"} end
      end

      field :either, :string do
        authorize any_of([check(:reasoned), check(:other_reasoned)])
        resolve fn _args, _resolution -> {:ok, "either"} end
      end
    end
  """

  @private_schema """
    object :item do
      field :id, :integer
      field :member_note, :string do
        authorize tenant_role(:member)
        resolve fn _item, _args, _resolution -> {:ok, "member note"} end
      end
    end

    query do
      field :quota, :string do
        authorize check(:reasoned)
        resolve fn _args, _resolution -> {:ok, "quota"} end
      end

      field :scoped_quota, :string do
        authorize role(:staff)
        arg :scope, :string
        authorize_args scope: check(:reasoned)
        resolve fn _args, _resolution -> {:ok, "quota"} end
      end

      field :items, list_of(:item) do
        resolve fn _args, _resolution ->
          items = [%{id: 1, tenant_id: "t1"}, %{id: 2, tenant_id: "t2"}]
          {:ok, items}
        end
      end
    end
  """

  test "expose_denial_reasons exposes reason atoms only, never the details map" do
    schema = compile_schema(@exposing_schema, "authorizer: Warden.Test.RedteamV2.ExposingAuthz")

    result = run(schema, "{ quota either }", abby())
    rendered = inspect(result)

    assert result.data == %{"quota" => nil, "either" => nil}
    refute rendered =~ "s3cr3t-detail"
    refute rendered =~ "abby@example.com"
    refute rendered =~ "trace"

    reasons =
      result.errors
      |> Enum.map(& &1.extensions.reason)
      |> Enum.sort()

    assert reasons == [["quota", "not_member"], "quota"]
  end

  test "the default error has no reason, no trace and no rule, for field and argument denials" do
    schema = compile_schema(@private_schema, "authorizer: Warden.Test.RedteamV2.Authz")

    field_denied = run(schema, "{ quota }", staff())
    argument_denied = run(schema, ~s|{ scopedQuota(scope: "all") }|, staff())

    for result <- [field_denied, argument_denied] do
      assert [%{message: "Forbidden", extensions: extensions}] = result.errors
      assert extensions == %{code: "FORBIDDEN"}
      refute inspect(result) =~ "quota_"
      refute inspect(result) =~ "s3cr3t-detail"
    end
  end

  test "tenant roles of one list item never answer for another item's tenant" do
    schema = compile_schema(@private_schema, "authorizer: Warden.Test.RedteamV2.Authz")

    result = run(schema, "{ items { id memberNote } }", abby())

    assert [%{"memberNote" => "member note"}, %{"memberNote" => nil}] = result.data["items"]
    assert_received {:tenant_roles, "abby", "t1"}
    assert_received {:tenant_roles, "abby", "t2"}
    refute_received {:tenant_roles, "abby", "t1"}
  end
end
