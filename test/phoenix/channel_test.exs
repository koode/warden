defmodule Warden.Phoenix.ChannelTest do
  use ExUnit.Case, async: false

  import Phoenix.ChannelTest

  alias Warden.{Denial, PolicyError, Rule}
  alias Warden.Phoenix.Channel
  alias Warden.Test.{ChannelAuthz, DefaultChannel, ManualChannel, RoomChannel, TimerChannel}
  alias Warden.Test.UserSocket

  @endpoint Warden.Test.Endpoint
  @pubsub Warden.Test.ChannelPubSub

  setup_all do
    Application.put_env(:warden, @endpoint, pubsub_server: @pubsub, server: false)
    start_supervised!({Phoenix.PubSub, name: @pubsub})
    start_supervised!(@endpoint)
    :ok
  end

  # A stopped channel exits its link to the test process; trapping turns that exit into
  # a message the test can assert on.
  setup do
    Process.flag(:trap_exit, true)
    {:ok, roles_agent} = Agent.start_link(fn -> [:member] end)
    %{roles_agent: roles_agent}
  end

  defp member_socket(roles_agent, rooms \\ ["1"]) do
    user = %{id: "u1", email: "abby@example.com", rooms: rooms, roles: [:member]}
    assigns = %{current_user: user, roles_agent: roles_agent, test_pid: self()}
    socket(UserSocket, "u1", assigns)
  end

  defp revoke(roles_agent), do: Agent.update(roles_agent, fn _roles -> [] end)

  defp flush_socket_context do
    receive do
      :socket_context -> flush_socket_context()
    after
      0 -> :ok
    end
  end

  describe "join" do
    test "an allowed join runs the channel's join/3", %{roles_agent: roles_agent} do
      assert {:ok, _reply, _socket} =
               subscribe_and_join(member_socket(roles_agent), RoomChannel, "room:1")

      assert_received :user_join_ran
    end

    test "a denied join is refused before the channel's join/3 runs", %{roles_agent: roles_agent} do
      assert {:error, %{reason: "forbidden"}} =
               subscribe_and_join(member_socket(roles_agent), RoomChannel, "room:2")

      refute_received :user_join_ran
    end

    test "an anonymous socket is refused as unauthorized" do
      socket = socket(UserSocket, nil, %{})
      assert {:error, %{reason: "unauthorized"}} = join(socket, RoomChannel, "room:1")
    end

    test "the configured default authorizer reads the socket assigns" do
      viewer = socket(UserSocket, "u2", %{current_user: %{id: "u2", roles: [:viewer]}})
      assert {:ok, %{"joined" => true}, _socket} = join(viewer, DefaultChannel, "default:1")

      nobody = socket(UserSocket, "u3", %{current_user: %{id: "u3", roles: []}})
      assert {:error, %{reason: "custom"}} = join(nobody, DefaultChannel, "default:1")
    end

    test "an on_deny handler that returns no map gets the default reply" do
      assigns = %{current_user: %{id: "u3", roles: []}, deny_mode: :garbage}
      socket = socket(UserSocket, "u3", assigns)
      assert {:error, %{reason: "forbidden"}} = join(socket, DefaultChannel, "default:1")
    end
  end

  describe "recheck: :every_push" do
    setup %{roles_agent: roles_agent} do
      {:ok, _reply, socket} =
        subscribe_and_join(member_socket(roles_agent), RoomChannel, "room:1")

      %{socket: socket}
    end

    test "an allowed broadcast is pushed, also for events the channel does not intercept" do
      @endpoint.broadcast!("room:1", "news", %{"n" => 1})
      assert_push("news", %{"n" => 1})
    end

    test "the channel's own handle_out/3 still runs for allowed pushes" do
      @endpoint.broadcast!("room:1", "edited", %{"n" => 2})
      assert_push("edited", %{"n" => 2, "by_handle_out" => true})
    end

    test "no push after a revocation; the channel stops", %{
      socket: socket,
      roles_agent: roles_agent
    } do
      revoke(roles_agent)
      @endpoint.broadcast!("room:1", "news", %{"secret" => "ALPHA"})

      assert_push("warden:denied", %{reason: "forbidden"})
      assert_receive {:EXIT, pid, {:shutdown, :forbidden}} when pid == socket.channel_pid
      refute_push("news", _payload)
    end

    test "the denial reaches the client without subject or value data",
         %{roles_agent: roles_agent} do
      revoke(roles_agent)
      @endpoint.broadcast!("room:1", "news", %{})

      assert_receive %Phoenix.Socket.Message{event: "warden:denied", payload: payload}
      assert payload == %{reason: "forbidden"}
      refute inspect(payload) =~ "abby@example.com"
      refute inspect(payload) =~ "u1"
    end

    test "the actor is built again on every check, so a changed assign takes effect",
         %{socket: socket} do
      flush_socket_context()

      @endpoint.broadcast!("room:1", "news", %{"n" => 1})
      assert_push("news", %{"n" => 1})
      assert_received :socket_context

      ref = push(socket, "leave_room", %{})
      assert_reply(ref, :ok)
      assert_received :socket_context

      @endpoint.broadcast!("room:1", "news", %{"n" => 2})
      assert_push("warden:denied", %{reason: "forbidden"})
      assert_received :socket_context
      refute_push("news", %{"n" => 2})
    end

    test "handle_in/3 is checked before it runs", %{socket: socket, roles_agent: roles_agent} do
      ref = push(socket, "ping", %{})
      assert_reply(ref, :ok, %{"pong" => true})

      revoke(roles_agent)
      ref = push(socket, "ping", %{})

      assert_push("warden:denied", %{reason: "forbidden"})
      refute_reply(ref, :ok, _payload)
    end

    test "handle_info/2 is checked before it runs", %{socket: socket, roles_agent: roles_agent} do
      send(socket.channel_pid, {:say, "hello"})
      assert_push("said", %{"text" => "hello"})

      revoke(roles_agent)
      send(socket.channel_pid, {:say, "after"})

      assert_push("warden:denied", %{reason: "forbidden"})
      refute_push("said", %{"text" => "after"})
    end

    test "every broadcast is intercepted" do
      assert "any_event" in RoomChannel.__intercepts__()
      assert TimerChannel.__intercepts__() == []
    end
  end

  describe "recheck: {:every, ms}" do
    setup %{roles_agent: roles_agent} do
      {:ok, _reply, socket} =
        subscribe_and_join(member_socket(roles_agent), TimerChannel, "timer:1", %{"room" => "1"})

      %{socket: socket}
    end

    test "the value comes from the join params" do
      socket = socket(UserSocket, "u1", %{current_user: %{rooms: ["1"], roles: [:member]}})

      assert {:error, %{reason: "forbidden"}} =
               join(socket, TimerChannel, "timer:1", %{"room" => "2"})
    end

    test "the timer stops an idle channel after access ends",
         %{socket: socket, roles_agent: roles_agent} do
      revoke(roles_agent)

      assert_push("warden:denied", %{reason: "forbidden"}, 1_000)
      assert_receive {:EXIT, pid, {:shutdown, :forbidden}} when pid == socket.channel_pid
    end

    test "the timer keeps an allowed channel open", %{socket: socket} do
      refute_receive {:EXIT, _pid, _reason}, 100
      assert Process.alive?(socket.channel_pid)
    end

    test "the channel's own handle_info/2 still runs", %{socket: socket} do
      send(socket.channel_pid, {:say, "hello"})
      assert_push("said", %{"text" => "hello"})
    end

    test "a recheck message from elsewhere starts no extra timer and is not passed on",
         %{socket: socket, roles_agent: roles_agent} do
      send(socket.channel_pid, {Channel, :recheck, make_ref()})
      revoke(roles_agent)

      assert_push("warden:denied", %{reason: "forbidden"}, 1_000)
      refute_push("warden:denied", _payload, 100)
    end
  end

  describe "by hand" do
    test "authorize_join/3 returns the join result", %{roles_agent: roles_agent} do
      assert {:ok, _reply, _socket} = join(member_socket(roles_agent), ManualChannel, "manual:1")

      assert {:error, %{reason: "forbidden"}} =
               join(member_socket(roles_agent), ManualChannel, "manual:2")

      assert {:error, %{reason: "unauthorized"}} =
               join(socket(UserSocket, nil, %{}), ManualChannel, "manual:1")
    end

    test "authorize/3 checks one message", %{roles_agent: roles_agent} do
      {:ok, _reply, socket} = join(member_socket(roles_agent), ManualChannel, "manual:1")
      ref = push(socket, "admin_only", %{})
      assert_reply(ref, :error, %{reason: "forbidden"})

      Agent.update(roles_agent, fn _roles -> [:admin] end)
      ref = push(socket, "admin_only", %{})
      assert_reply(ref, :ok)
    end

    test "authorize/3 returns the denial and actor/2 builds a fresh actor",
         %{roles_agent: roles_agent} do
      socket = member_socket(roles_agent)
      opts = [authorizer: ChannelAuthz]

      assert {:error, %Denial{kind: :call}} =
               Channel.authorize(socket, Rule.role(:admin), opts)

      assert {:ok, ^socket} =
               Channel.authorize(socket, Rule.role(:member), opts)

      actor = Channel.actor(socket, opts)
      assert MapSet.member?(actor.roles, :member)
    end

    test "an unknown role raises Warden.PolicyError", %{roles_agent: roles_agent} do
      assert_raise PolicyError, fn ->
        Channel.authorize(member_socket(roles_agent), Rule.role(:ghost), authorizer: ChannelAuthz)
      end
    end
  end
end
