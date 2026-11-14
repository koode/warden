defmodule Warden.RedteamV2.ChannelTest do
  # "Nothing is pushed after access ends."
  use ExUnit.Case, async: false

  import Phoenix.ChannelTest

  alias Warden.RedteamV2.FarewellChannel
  alias Warden.Test.{RoomChannel, TimerChannel, UserSocket}

  @endpoint Warden.Test.Endpoint
  @pubsub Warden.Test.ChannelPubSub

  setup_all do
    Application.put_env(:warden, @endpoint, pubsub_server: @pubsub, server: false)
    start_supervised!({Phoenix.PubSub, name: @pubsub})
    start_supervised!(@endpoint)
    :ok
  end

  setup do
    Process.flag(:trap_exit, true)
    {:ok, roles_agent} = Agent.start_link(fn -> [:member] end)
    user = %{id: "u1", rooms: ["1"], roles: [:member]}
    socket = socket(UserSocket, "u1", %{current_user: user, roles_agent: roles_agent})
    %{socket: socket, roles_agent: roles_agent}
  end

  defp revoke(roles_agent), do: Agent.update(roles_agent, fn _roles -> [] end)

  describe "holes" do
    # Decided: Warden does not wrap terminate/2. It runs after a denial with reason
    # {:shutdown, :forbidden}, and the guides say it must not push.
    test "terminate/2 runs after the denial with reason {:shutdown, :forbidden}",
         %{socket: socket, roles_agent: roles_agent} do
      socket = Phoenix.Socket.assign(socket, :test_pid, self())
      {:ok, _reply, channel} = subscribe_and_join(socket, FarewellChannel, "farewell:1")
      revoke(roles_agent)

      push(channel, "ping", %{})

      assert_push("warden:denied", _reply)
      assert_receive {:terminated, {:shutdown, :forbidden}}
    end
  end

  describe "defended" do
    test "a callback that drops Warden's socket state fails closed", %{socket: socket} do
      {:ok, _reply, channel} = subscribe_and_join(socket, FarewellChannel, "farewell:2")
      monitor = Process.monitor(channel.channel_pid)

      push(channel, "drop_state", %{})
      push(channel, "ping", %{})

      assert_receive {:DOWN, ^monitor, :process, _pid, {%Warden.PolicyError{}, _stack}}
    end

    test "broadcasts of any event, after revocation, are not pushed",
         %{socket: socket, roles_agent: roles_agent} do
      {:ok, _reply, _channel} = subscribe_and_join(socket, RoomChannel, "room:1")
      revoke(roles_agent)

      @endpoint.broadcast!("room:1", "never_intercepted", %{"secret" => "x"})

      assert_push("warden:denied", _reply)
      refute_push("never_intercepted", _payload, 100)
    end

    test "a forged recheck message with a guessed ref neither grants nor stops the timer",
         %{socket: socket} do
      {:ok, _reply, channel} =
        subscribe_and_join(socket, TimerChannel, "timer:1", %{"room" => "1"})

      send(channel.channel_pid, {Warden.Phoenix.Channel, :recheck, make_ref()})
      send(channel.channel_pid, {:say, "still checked"})

      assert_push("said", %{"text" => "still checked"})
    end
  end
end
