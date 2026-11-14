defmodule Warden.TenantOptionTest do
  use ExUnit.Case, async: true

  import Plug.Conn, only: [assign: 3]
  import Plug.Test
  import Warden.Rule
  import Warden.Test.V2.People

  alias Warden.Credential
  alias Warden.Test.V2.Authz

  defp bound(user, tenant),
    do: actor(user, %{credential: %Credential{method: :api_key, scopes: :all, tenant: tenant}})

  test "a bound actor is refused for another explicit tenant before the rule runs" do
    key = bound(abby(), "t1")
    assert {:error, denial} = Warden.authorize(key, public(), value: "doc-9", tenant: "t2")
    assert denial.reason == :tenant_binding
    assert Warden.allowed?(key, authenticated(), value: "doc-9", tenant: "t1")
    refute Warden.allowed?(key, authenticated(), value: "doc-9", tenant: "t2")
    assert Warden.filter(key, public(), ["a", "b"], tenant: "t2") == []
    assert Warden.explain(key, public(), tenant: "t2").result == :deny
  end

  test "without the option a bare id keeps today's behaviour" do
    assert Warden.allowed?(bound(abby(), "t1"), authenticated(), value: "doc-9")
  end

  test "the explicit tenant feeds tenant_role when the value has none" do
    assert Warden.allowed?(actor(sam()), tenant_role(:member), value: "doc-9", tenant: "t1")
    refute Warden.allowed?(actor(sam()), tenant_role(:member), value: "doc-9", tenant: "t2")
    refute Warden.allowed?(actor(sam()), tenant_role(:member), value: "doc-9")
    # A value with a tenant of its own wins.
    refute Warden.allowed?(actor(sam()), tenant_role(:member),
             value: %{tenant_id: "t2"},
             tenant: "t1"
           )
  end

  test "a bound system actor is refused for another tenant" do
    webhook = Warden.system_actor(Authz, kind: :webhook, tenant: "t1")
    refute Warden.allowed?(webhook, check(:hooked), tenant: "t2")
    assert Warden.allowed?(webhook, check(:hooked), tenant: "t1")
  end

  describe "Warden.Plug" do
    defp conn_for(user, tenant, credential_tenant) do
      credential = %Credential{method: :api_key, scopes: :all, tenant: credential_tenant}

      :get
      |> conn("/workspaces/#{tenant}")
      |> assign(:current_user, user)
      |> assign(:credential, credential)
      |> assign(:workspace_id, tenant)
    end

    def workspace_id(conn), do: conn.assigns.workspace_id

    test "init takes tenant: as a function of the conn" do
      plug =
        Warden.Plug.init(
          rule: tenant_role(:guest),
          tenant: &__MODULE__.workspace_id/1,
          authorizer: Authz
        )

      refute Warden.Plug.call(conn_for(abby(), "t1", "t1"), plug).halted
      assert Warden.Plug.call(conn_for(abby(), "t2", "t1"), plug).status == 403
    end

    test "authorize/3 takes tenant:" do
      conn = conn_for(abby(), "t2", "t1")

      assert {:error, %{reason: :tenant_binding}} =
               Warden.Plug.authorize(conn, public(), tenant: "t2", authorizer: Authz)

      assert {:ok, _conn} = Warden.Plug.authorize(conn, public(), tenant: "t1", authorizer: Authz)
    end

    test "init refuses a tenant: that is not a function of the conn" do
      assert_raise ArgumentError, ~r/`tenant:` must be a function of the conn/, fn ->
        Warden.Plug.init(rule: public(), tenant: "t1", authorizer: Authz)
      end
    end
  end
end
