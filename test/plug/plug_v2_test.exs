defmodule Warden.PlugV2Test do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test
  import Warden.Rule
  import Warden.Test.V2.People

  alias Warden.Credential
  alias Warden.Test.Decisions
  alias Warden.Test.V2.{Authz, Doc, Docs}

  defp conn_for(user, assigns \\ %{}) do
    conn = conn(:get, "/docs")
    assigns = Map.merge(%{current_user: user, test_pid: self()}, assigns)
    Enum.reduce(assigns, conn, fn {key, value}, conn -> assign(conn, key, value) end)
  end

  describe "rules" do
    test "policies, tenant roles and credentials work on a conn" do
      plug = Warden.Plug.init(rule: all_of([session(), can(Docs, :write)]), authorizer: Authz)

      assert {:ok, _conn} =
               Warden.Plug.authorize(conn_for(abby()), can(Docs, :read),
                 value: Doc.get(1),
                 authorizer: Authz
               )

      assert {:error, %Warden.Denial{}} =
               Warden.Plug.authorize(conn_for(sam()), can(Docs, :read),
                 value: Doc.get(1),
                 authorizer: Authz
               )

      assert {:ok, _conn} =
               Warden.Plug.authorize(conn_for(sam()), tenant_role(:member),
                 value: %{tenant_id: "t1"},
                 authorizer: Authz
               )

      key = %Credential{method: :api_key, scopes: ["docs:read"]}
      conn = Warden.Plug.call(conn_for(abby(), %{credential: key}), plug)
      assert conn.halted
      assert conn.status == 403
    end

    test "init/1 refuses covered(), unknown tenant roles and bad check options" do
      for rule <- [covered(), tenant_role(:viewer), check(:typed), can(Docs, :delete)] do
        assert_raise ArgumentError, ~r/invalid Warden.Plug rule for/, fn ->
          Warden.Plug.init(rule: rule, authorizer: Authz)
        end
      end
    end

    test "a check reason reaches the denial, not the response" do
      plug = Warden.Plug.init(rule: check(:reasoned), authorizer: Authz)
      conn = Warden.Plug.call(conn_for(abby(), %{reasoned: {:deny, :not_member}}), plug)
      assert conn.status == 403
      assert conn.resp_body == "Forbidden"

      assert {:error, %{reason: :not_member}} =
               Warden.Plug.authorize(
                 conn_for(abby(), %{reasoned: {:deny, :not_member}}),
                 check(:reasoned),
                 authorizer: Authz
               )
    end

    test "an anonymous conn still gets 401" do
      plug = Warden.Plug.init(rule: tenant_role(:guest), authorizer: Authz)
      assert Warden.Plug.call(conn_for(nil), plug).status == 401
    end
  end

  describe "telemetry" do
    test "the plug and Warden.Plug.authorize/3 report layer :plug, the core API :core" do
      Decisions.attach()
      plug = Warden.Plug.init(rule: session(), authorizer: Authz)
      Warden.Plug.call(conn_for(abby()), plug)
      Warden.Plug.authorize(conn_for(abby()), session(), authorizer: Authz)
      Warden.authorize(context(abby()), session(), authorizer: Authz)

      assert_received {:decision, %{count: 1}, %{layer: :plug, kind: :call, result: :ok}}
      assert_received {:decision, %{count: 1}, %{layer: :plug}}
      assert_received {:decision, %{count: 1}, %{layer: :core}}
    end
  end

  describe "the core API takes system and delegated actors" do
    test "authorize, allowed?, authorize! and filter" do
      webhook = Warden.system_actor(Authz, kind: :webhook)
      assert Warden.authorize(webhook, kind(:webhook)) == :ok
      assert Warden.allowed?(webhook, can(Docs, :read), value: Doc.get(3))
      refute Warden.allowed?(webhook, can(Docs, :read), value: Doc.get(1))
      assert_raise Warden.ForbiddenError, fn -> Warden.authorize!(webhook, authenticated()) end
      assert Warden.filter(webhook, can(Docs, :read), Doc.all()) |> Enum.map(& &1.id) == [3, 5]

      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))
      assert Warden.authorize(delegated, can(Docs, :read), value: Doc.get(5)) == :ok
      assert {:error, _denial} = Warden.authorize(delegated, can(Docs, :read), value: Doc.get(1))
    end

    test "an explicit authorizer that differs from the actor's still raises" do
      webhook = Warden.system_actor(Authz, kind: :webhook)

      assert_raise Warden.PolicyError, fn ->
        Warden.authorize(webhook, public(), authorizer: Warden.Test.Authz)
      end
    end
  end
end
