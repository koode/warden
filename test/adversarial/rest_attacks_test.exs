defmodule Warden.Adversarial.RestAttacksTest do
  @moduledoc """
  Attacks on the core API and `Warden.Plug`, one test per attempted bypass.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test
  import Warden.Rule

  alias Warden.{Actor, ForbiddenError, PolicyError}

  defmodule OtherAuthz do
    @moduledoc false
    use Warden.Authorizer, roles: [:admin, :viewer]

    @impl true
    def subject(ctx), do: ctx[:current_user]

    @impl true
    def roles(user, _), do: user.roles
  end

  # The application's authentication: the user comes from a trusted server-side lookup
  # keyed by a session id, never from what the client sends.
  defmodule App do
    @moduledoc false
    use Plug.Builder

    plug(Plug.Parsers,
      parsers: [:urlencoded, :json],
      json_decoder: JSON
    )

    plug(:authenticate)
    plug(Warden.Plug, rule: role(:admin))
    plug(:admin_area)

    @users %{
      "s-viewer" => %{id: "u2", roles: [:viewer]},
      "s-admin" => %{id: "u1", roles: [:admin]}
    }

    def authenticate(conn, _) do
      session = get_req_header(conn, "x-session") |> List.first()
      assign(conn, :current_user, Map.get(@users, session))
    end

    def admin_area(conn, _), do: send_resp(conn, 200, "ADMIN AREA")
  end

  defp viewer_conn(conn), do: put_req_header(conn, "x-session", "s-viewer")

  test "client sends roles, a user or an actor through query params" do
    conn =
      conn(
        :get,
        "/?current_user[id]=u1&current_user[roles][]=admin&warden_actor=admin&role=admin"
      )
      |> viewer_conn()
      |> App.call([])

    assert {conn.status, conn.halted} == {403, true}
    refute conn.resp_body =~ "ADMIN"
  end

  test "client sends a forged identity through headers" do
    conn =
      conn(:get, "/")
      |> put_req_header("x-current-user", "u1")
      |> put_req_header("x-warden-actor", "admin")
      |> put_req_header("x-roles", "admin")
      |> App.call([])

    assert {conn.status, conn.halted} == {401, true}
  end

  test "client sends a forged identity in a JSON body" do
    conn =
      conn(:post, "/", ~s({"current_user": {"roles": ["admin"]}}))
      |> put_req_header("content-type", "application/json")
      |> viewer_conn()
      |> App.call([])

    assert conn.status == 403
    assert conn.params["current_user"] == %{"roles" => ["admin"]}
  end

  test "an actor planted in conn.private[:warden_actor] has no effect" do
    planted = Warden.actor(%{current_user: %{id: "u9", roles: [:admin]}}, authorizer: OtherAuthz)
    admin = Warden.actor(%{current_user: %{id: "u1", roles: [:admin]}})

    for value <- [
          planted,
          admin,
          %{Warden.Test.Authz => admin},
          %{Warden.Test.Authz => {nil, admin}}
        ] do
      conn = conn(:get, "/") |> put_private(:warden_actor, value)
      conn = Warden.Plug.call(conn, Warden.Plug.init(rule: role(:admin)))
      assert {conn.status, conn.halted} == {401, true}
    end
  end

  test "stale actor: the tenant switches the org roles, same subject" do
    defmodule OrgAuthz do
      @moduledoc false
      use Warden.Authorizer, roles: [:admin, :viewer]

      @impl true
      def subject(ctx), do: ctx[:current_user]

      @impl true
      def roles(user, ctx), do: ctx[:org_roles] || user.roles
    end

    user = %{id: "u1", roles: []}

    conn =
      conn(:get, "/")
      |> assign(:current_user, user)
      |> assign(:org_roles, [:admin])

    assert {:ok, conn} = Warden.Plug.authorize(conn, role(:admin), authorizer: OrgAuthz)

    conn = assign(conn, :org_roles, [:viewer])
    assert {:error, _} = Warden.Plug.authorize(conn, role(:admin), authorizer: OrgAuthz)

    halted = Warden.Plug.call(conn, Warden.Plug.init(rule: role(:admin), authorizer: OrgAuthz))
    assert {halted.status, halted.halted} == {403, true}
  end

  test "a hand-built actor with admin roles is refused by the core API" do
    forged = %Actor{subject: %{id: "x"}, roles: MapSet.new([:admin])}

    assert_raise PolicyError, ~r/has no authorizer/, fn ->
      apply(Warden, :authorize, [forged, role(:admin)])
    end
  end

  test "an actor built by one authorizer checked under another" do
    actor = Warden.actor(%{current_user: %{id: "u1", roles: [:admin]}}, authorizer: OtherAuthz)

    assert_raise PolicyError, fn ->
      Warden.authorize(actor, role(:admin), authorizer: Warden.Test.Authz)
    end

    assert_raise PolicyError, fn ->
      Warden.filter(actor, role(:admin), [1], authorizer: Warden.Test.Authz)
    end
  end

  test "stale cached actor: the user is switched to a viewer mid-request (sudo drop)" do
    conn = conn(:get, "/") |> assign(:current_user, %{id: "u1", roles: [:admin]})
    assert {:ok, conn} = Warden.Plug.authorize(conn, role(:admin))

    conn = assign(conn, :current_user, %{id: "u2", roles: [:viewer]})
    assert {:error, _} = Warden.Plug.authorize(conn, role(:admin))
  end

  test "stale cached actor: logout before a plug that requires authentication" do
    conn = conn(:get, "/") |> assign(:current_user, %{id: "u1", roles: [:admin]})
    assert {:ok, conn} = Warden.Plug.authorize(conn, authenticated())

    conn = assign(conn, :current_user, nil)
    conn = Warden.Plug.call(conn, Warden.Plug.init(rule: authenticated()))
    assert {conn.status, conn.halted} == {401, true}
  end

  test "stale cached actor: only the roles in the same user struct change" do
    user = %{id: "u1", roles: [:admin]}
    conn = conn(:get, "/") |> assign(:current_user, user)
    assert {:ok, conn} = Warden.Plug.authorize(conn, role(:admin))

    conn = assign(conn, :current_user, %{user | roles: [:viewer]})
    assert {:error, _} = Warden.Plug.authorize(conn, role(:admin))

    # And back: the cache follows the current user in both directions.
    conn = assign(conn, :current_user, user)
    assert {:ok, _} = Warden.Plug.authorize(conn, role(:admin))
  end

  @secret_user %{
    id: "u2",
    roles: [:viewer],
    email: "viewer@secret.example",
    token: "tok-SECRET-123"
  }
  @secret_post %{id: "p1", owner: "u1", body: "PRIVATE-BODY-456"}

  defp refute_leak(term) do
    output = inspect(term)

    for secret <- ["secret.example", "tok-SECRET-123", "PRIVATE-BODY-456"] do
      refute output =~ secret, "#{secret} leaked in: #{output}"
    end

    output
  end

  test "inspect of a core API denial leaks neither the subject nor the resource" do
    {:error, denial} =
      Warden.authorize(%{current_user: @secret_user}, check(:self), value: @secret_post)

    output = refute_leak(denial)
    assert output =~ "kind: :call"
    assert output =~ "failed_rule:"
    # Still available to code.
    assert denial.actor.subject.email == "viewer@secret.example"
  end

  test "inspect of a Warden.Plug.authorize/3 denial leaks neither the subject nor the resource" do
    conn = conn(:get, "/") |> assign(:current_user, @secret_user)
    {:error, denial} = Warden.Plug.authorize(conn, check(:self), value: @secret_post)
    refute_leak(denial)
  end

  test "inspect of an actor shows roles but never the subject" do
    actor = Warden.actor(%{current_user: @secret_user})
    output = refute_leak(actor)
    assert output =~ "#Warden.Actor<"
    assert output =~ ":viewer"
    assert output =~ "anonymous: false"
    assert output =~ "Warden.Test.Authz"
    assert Map.from_struct(actor).subject.token == "tok-SECRET-123"
  end

  test "inspect of a ForbiddenError leaks no subject or resource data" do
    error =
      assert_raise ForbiddenError, fn ->
        Warden.authorize!(%{current_user: @secret_user}, check(:self), value: @secret_post)
      end

    refute_leak(error)
  end

  test "ForbiddenError inspect output does not include the user record" do
    user = %{id: "u2", roles: [:viewer], email: "viewer@secret.example", token: "tok-123"}

    error =
      assert_raise ForbiddenError, fn ->
        Warden.authorize!(%{current_user: user}, role(:admin))
      end

    refute inspect(error) =~ "secret.example"
    refute inspect(error) =~ "tok-123"
    assert inspect(error) =~ "Forbidden"
    # Still available to code.
    assert error.denial.actor.subject.email == "viewer@secret.example"
  end

  test "a rule built from untrusted input that names an unknown role fails closed" do
    requested = String.to_atom("ad" <> "mn")

    assert_raise PolicyError, fn ->
      Warden.allowed?(%{current_user: %{id: "u1", roles: [:admin]}}, role(requested))
    end
  end

  test "truthy check results through filter" do
    users = [%{id: "u1"}, %{id: "u2"}]

    assert_raise PolicyError, fn ->
      Warden.filter(
        %{current_user: %{id: "u1", roles: []}, check_result: :ok},
        check(:configured),
        users
      )
    end
  end

  test "denial responses and errors reveal nothing about missing roles" do
    conn = conn(:get, "/") |> viewer_conn() |> App.call([])
    assert conn.resp_body == "Forbidden"

    error =
      assert_raise ForbiddenError, fn ->
        Warden.authorize!(%{current_user: %{id: "u2", roles: [:viewer]}}, role(:admin))
      end

    assert Exception.message(error) == "Forbidden"
    refute Exception.message(error) =~ "admin"
  end

  test "a context that is neither a map nor an actor" do
    for bad <- [nil, "u1", [current_user: %{roles: [:admin]}], {:admin}] do
      assert_raise ArgumentError, fn -> apply(Warden, :authorize, [bad, role(:admin)]) end
    end
  end
end
