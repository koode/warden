defmodule Warden.PlugTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test
  import Warden.Rule

  alias Warden.{Actor, Denial, ForbiddenError, PolicyError}

  # Authorizer with the Plug callbacks; the test picks the deny_conn behaviour through
  # an assign, and conn_context reports to the test process.
  defmodule ConnAuthz do
    @moduledoc false
    use Warden.Authorizer, roles: [:admin, :viewer], checks: [:owner]

    @impl true
    def subject(ctx), do: ctx[:current_user]

    @impl true
    def roles(user, ctx) do
      if pid = ctx[:test_pid], do: send(pid, {:roles_called, user.id})
      user.roles
    end

    @impl true
    def check(:owner, %Warden.Check{actor: actor, value: value}),
      do: is_map(value) and value[:owner] == actor.subject.id

    @impl true
    def conn_context(conn) do
      %{current_user: conn.assigns[:user], test_pid: conn.assigns[:test_pid], conn: conn}
    end

    @impl true
    def deny_conn(conn, denial) do
      case conn.assigns[:deny_mode] do
        # Forgets to halt and to send.
        :forget -> conn
        # Sends a custom response but forgets to halt.
        :teapot -> send_resp(conn, 418, "no")
        # Sets a response without sending or halting.
        :set_only -> resp(conn, 409, "set")
        # Returns something that is not a conn.
        :garbage -> {:ok, denial}
        _ -> conn |> send_resp(451, "custom") |> halt()
      end
    end
  end

  defmodule Handler do
    @moduledoc false
    def on_deny(conn, %Denial{}), do: send_resp(conn, 402, "pay")
    def on_deny_forget(conn, _denial), do: conn
    def on_deny_arity1(conn), do: conn
  end

  # A pipeline: the Warden plug, then a plug that must not run on denial.
  defmodule Pipeline do
    @moduledoc false
    use Plug.Builder

    plug(Warden.Plug, rule: role(:admin))
    plug(:reached)

    def reached(conn, _), do: conn |> put_private(:reached, true) |> send_resp(200, "ok")
  end

  defmodule Double do
    @moduledoc false
    use Plug.Builder

    plug(Warden.Plug, rule: authenticated(), authorizer: Warden.PlugTest.ConnAuthz)
    plug(Warden.Plug, rule: role(:viewer), authorizer: Warden.PlugTest.ConnAuthz)
    plug(:reached)

    def reached(conn, _), do: send_resp(conn, 200, "ok")
  end

  defp conn_as(user, assigns \\ %{}) do
    conn = conn(:get, "/") |> assign(:current_user, user) |> assign(:user, user)
    Enum.reduce(assigns, conn, fn {k, v}, conn -> assign(conn, k, v) end)
  end

  defp admin, do: %{id: "u1", roles: [:admin]}
  defp viewer, do: %{id: "u2", roles: [:viewer]}

  describe "as a plug (configured default authorizer)" do
    test "an allowed request continues" do
      conn = Pipeline.call(conn_as(admin()), [])
      assert conn.status == 200
      assert conn.private[:reached]
      refute conn.halted
    end

    test "a denied request is halted with 403, and later plugs do not run" do
      conn = Pipeline.call(conn_as(viewer()), [])
      assert conn.status == 403
      assert conn.resp_body == "Forbidden"
      assert conn.halted
      refute conn.private[:reached]
    end

    test "an anonymous request gets 401" do
      conn = Pipeline.call(conn_as(nil), [])
      assert conn.status == 401
      assert conn.resp_body == "Unauthorized"
      assert conn.halted
    end
  end

  describe "explicit authorizer and handlers" do
    defp call(conn, opts), do: Warden.Plug.call(conn, Warden.Plug.init(opts))

    test "deny_conn on the authorizer handles the denial" do
      conn = call(conn_as(nil), rule: role(:admin), authorizer: ConnAuthz)
      assert {conn.status, conn.resp_body, conn.halted} == {451, "custom", true}
    end

    test "a handler that forgets to halt and to send: halted, default response" do
      conn =
        call(conn_as(viewer(), deny_mode: :forget), rule: role(:admin), authorizer: ConnAuthz)

      assert {conn.status, conn.halted} == {403, true}
    end

    test "a handler that sends but forgets to halt: halted, its response kept" do
      conn =
        call(conn_as(viewer(), deny_mode: :teapot), rule: role(:admin), authorizer: ConnAuthz)

      assert {conn.status, conn.resp_body, conn.halted} == {418, "no", true}
    end

    test "a handler that only sets a response: sent and halted" do
      conn =
        call(conn_as(viewer(), deny_mode: :set_only), rule: role(:admin), authorizer: ConnAuthz)

      assert {conn.status, conn.state, conn.halted} == {409, :sent, true}
    end

    test "a handler that returns something else: halted, default response" do
      conn =
        call(conn_as(viewer(), deny_mode: :garbage), rule: role(:admin), authorizer: ConnAuthz)

      assert {conn.status, conn.halted} == {403, true}
    end

    test "on_deny overrides deny_conn" do
      conn =
        call(conn_as(viewer()),
          rule: role(:admin),
          authorizer: ConnAuthz,
          on_deny: {Handler, :on_deny}
        )

      assert {conn.status, conn.halted} == {402, true}

      conn =
        call(conn_as(nil),
          rule: role(:admin),
          authorizer: ConnAuthz,
          on_deny: {Handler, :on_deny_forget}
        )

      assert {conn.status, conn.halted} == {401, true}
    end
  end

  describe "the actor cache" do
    test "built once per conn, cached in conn.private keyed by authorizer" do
      conn = Double.call(conn_as(viewer(), test_pid: self()), [])
      assert conn.status == 200
      assert_received {:roles_called, "u2"}
      refute_received {:roles_called, _}

      assert %{ConnAuthz => {%{id: "u2"}, %Actor{authorizer: ConnAuthz}}} =
               conn.private[:warden_actor]
    end

    test "never shared across conns" do
      Double.call(conn_as(viewer(), test_pid: self()), [])
      Double.call(conn_as(admin(), test_pid: self()), [])
      assert_received {:roles_called, "u2"}
      assert_received {:roles_called, "u1"}
    end

    test "Warden.Plug.actor/2 returns the cached actor" do
      {conn, actor} =
        Warden.Plug.actor(conn_as(viewer(), test_pid: self()), authorizer: ConnAuthz)

      {_conn, ^actor} = Warden.Plug.actor(conn, authorizer: ConnAuthz)
      assert_received {:roles_called, "u2"}
      refute_received {:roles_called, _}
    end
  end

  describe "Warden.Plug.authorize/3 and authorize!/3" do
    test "resource checks in a controller, explicit authorizer" do
      post = %{owner: "u2"}

      assert {:ok, conn} =
               Warden.Plug.authorize(conn_as(viewer()), check(:owner),
                 value: post,
                 authorizer: ConnAuthz
               )

      assert conn.private[:warden_actor][ConnAuthz]
      refute conn.halted
      assert conn.state == :unset

      assert {:error, %Denial{kind: :call}} =
               Warden.Plug.authorize(conn_as(admin()), check(:owner),
                 value: post,
                 authorizer: ConnAuthz
               )
    end

    test "with the configured default authorizer" do
      assert {:ok, _} = Warden.Plug.authorize(conn_as(admin()), role(:admin))
      assert {:error, _} = Warden.Plug.authorize(conn_as(viewer()), role(:admin))
    end

    test "authorize! returns the conn or raises ForbiddenError (403)" do
      assert %Plug.Conn{} = Warden.Plug.authorize!(conn_as(admin()), role(:admin))

      error =
        assert_raise ForbiddenError, fn ->
          Warden.Plug.authorize!(conn_as(viewer()), role(:admin))
        end

      assert error.plug_status == 403
      assert Plug.Exception.status(error) == 403
    end

    test "unknown roles raise PolicyError at runtime" do
      assert_raise PolicyError, fn -> Warden.Plug.authorize(conn_as(admin()), role(:ghost)) end
    end
  end

  describe "init/1" do
    test "rejects unknown roles, permissions and checks" do
      for rule <- [role(:ghost), check(:nope), any_of([role(:admin), role(:x)])] do
        assert_raise ArgumentError, ~r/invalid Warden.Plug rule for/, fn ->
          Warden.Plug.init(rule: rule, authorizer: ConnAuthz)
        end
      end

      assert_raise ArgumentError, ~r/permission "nope"/, fn ->
        Warden.Plug.init(rule: permission("nope"))
      end
    end

    test "on_deny must name an existing module and function of arity 2" do
      assert %{on_deny: {Handler, :on_deny}} =
               Warden.Plug.init(rule: public(), on_deny: {Handler, :on_deny})

      for bad <- [{Handler, :missing}, {Warden.NoSuchHandler, :deny}, {Handler, :on_deny_arity1}] do
        assert_raise ArgumentError, ~r/does not exist/, fn ->
          Warden.Plug.init(rule: public(), on_deny: bad)
        end
      end
    end

    test "rejects a missing rule, unknown options, bad on_deny and non-authorizers" do
      assert_raise ArgumentError, ~r/needs a `rule:`/, fn -> Warden.Plug.init([]) end

      assert_raise ArgumentError, ~r/unknown Warden.Plug options/, fn ->
        Warden.Plug.init(rule: public(), halt: false)
      end

      assert_raise ArgumentError, ~r/on_deny/, fn ->
        Warden.Plug.init(rule: public(), on_deny: fn _, _ -> :ok end)
      end

      assert_raise ArgumentError, ~r/must `use Warden.Authorizer`/, fn ->
        Warden.Plug.init(rule: public(), authorizer: Enum)
      end
    end

    test "a typo fails compilation of a Plug.Builder pipeline" do
      assert_raise ArgumentError, fn ->
        Code.compile_string("""
        defmodule Warden.PlugTest.Typo#{System.unique_integer([:positive])} do
          use Plug.Builder
          import Warden.Rule
          plug Warden.Plug, rule: role(:adnim)
        end
        """)
      end
    end
  end
end
