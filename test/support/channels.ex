defmodule Warden.Test.ChannelAuthz do
  @moduledoc false
  use Warden.Authorizer, roles: [:member, :admin], checks: [:room_member]

  @impl true
  def subject(context), do: context[:current_user]

  # Roles come from an agent when the socket has one, so a test can revoke them while
  # the channel runs.
  @impl true
  def roles(user, context) do
    case context[:roles_agent] do
      nil -> user.roles
      agent -> Agent.get(agent, fn roles -> roles end)
    end
  end

  @impl true
  def check(:room_member, %Warden.Check{actor: %{subject: %{rooms: rooms}}, value: room_id}) do
    room_id in rooms
  end

  def check(:room_member, %Warden.Check{}), do: false

  # Reports every call, so a test can see that every check builds the actor again.
  @impl true
  def socket_context(socket) do
    if test_pid = socket.assigns[:test_pid], do: send(test_pid, :socket_context)
    socket.assigns
  end
end

defmodule Warden.Test.Endpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :warden
end

defmodule Warden.Test.UserSocket do
  @moduledoc false
  use Phoenix.Socket

  channel("room:*", Warden.Test.RoomChannel)
  channel("timer:*", Warden.Test.TimerChannel)
  channel("default:*", Warden.Test.DefaultChannel)
  channel("manual:*", Warden.Test.ManualChannel)

  @impl true
  def connect(_params, socket, _connect_info), do: {:ok, socket}

  @impl true
  def id(_socket), do: nil
end

defmodule Warden.Test.RoomChannel do
  @moduledoc false
  # Rechecks on every push, with the user's own handle_out/3, handle_in/3 and
  # handle_info/2.
  use Phoenix.Channel
  import Warden.Rule

  use Warden.Phoenix.Channel,
    rule: all_of([role(:member), check(:room_member)]),
    value: &room_id/1,
    recheck: :every_push,
    authorizer: Warden.Test.ChannelAuthz

  intercept(["edited"])

  @impl true
  def join("room:" <> _id, _params, socket) do
    if test_pid = socket.assigns[:test_pid], do: send(test_pid, :user_join_ran)
    {:ok, socket}
  end

  @impl true
  def handle_in("leave_room", _payload, socket) do
    user = %{socket.assigns.current_user | rooms: []}
    {:reply, :ok, assign(socket, :current_user, user)}
  end

  def handle_in("ping", _payload, socket) do
    reply = %{"pong" => true}
    {:reply, {:ok, reply}, socket}
  end

  @impl true
  def handle_out("edited", payload, socket) do
    edited = Map.put(payload, "by_handle_out", true)
    push(socket, "edited", edited)
    {:noreply, socket}
  end

  @impl true
  def handle_info({:say, text}, socket) do
    push(socket, "said", %{"text" => text})
    {:noreply, socket}
  end

  defp room_id("room:" <> id), do: id
end

defmodule Warden.Test.TimerChannel do
  @moduledoc false
  # Rechecks on a timer only, with a value read from the join params.
  use Phoenix.Channel
  import Warden.Rule

  use Warden.Phoenix.Channel,
    rule: all_of([role(:member), check(:room_member)]),
    value: fn _topic, params -> params["room"] end,
    recheck: [{:every, 20}],
    authorizer: Warden.Test.ChannelAuthz

  @impl true
  def join("timer:" <> _id, _params, socket), do: {:ok, socket}

  @impl true
  def handle_info({:say, text}, socket) do
    push(socket, "said", %{"text" => text})
    {:noreply, socket}
  end
end

defmodule Warden.Test.DefaultChannel do
  @moduledoc false
  # The configured default authorizer, the default socket context and an on_deny
  # handler; checked at join only.
  use Phoenix.Channel
  import Warden.Rule

  use Warden.Phoenix.Channel,
    rule: role(:viewer),
    recheck: [],
    on_deny: {__MODULE__, :deny}

  @impl true
  def join("default:" <> _id, _params, socket), do: {:ok, %{"joined" => true}, socket}

  def deny(socket, %Warden.Denial{}) do
    case socket.assigns[:deny_mode] do
      :garbage -> :not_a_map
      _custom -> %{reason: "custom"}
    end
  end
end

defmodule Warden.Test.ManualChannel do
  @moduledoc false
  # Checks by hand, without `use Warden.Phoenix.Channel`.
  use Phoenix.Channel
  import Warden.Rule

  @impl true
  def join("manual:" <> id, _params, socket) do
    Warden.Phoenix.Channel.authorize_join(socket, check(:room_member),
      value: id,
      authorizer: Warden.Test.ChannelAuthz
    )
  end

  @impl true
  def handle_in("admin_only", _payload, socket) do
    case Warden.Phoenix.Channel.authorize(socket, role(:admin),
           authorizer: Warden.Test.ChannelAuthz
         ) do
      {:ok, socket} ->
        {:reply, :ok, socket}

      {:error, %Warden.Denial{}} ->
        reply = %{reason: "forbidden"}
        {:reply, {:error, reply}, socket}
    end
  end
end
