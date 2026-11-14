# Phoenix channels

`Warden.Phoenix.Channel` checks a rule when a client joins a channel and again while the
channel lives. When access ends, the client gets a reason and the channel stops. Nothing
is pushed after that.

It needs the `phoenix` dependency. Without it, the module is not compiled.

## A guarded channel

```elixir
defmodule MyAppWeb.WorkspaceChannel do
  use Phoenix.Channel
  import Warden.Rule

  use Warden.Phoenix.Channel,
    rule: check(:workspace_member),
    value: &workspace_id/1,
    recheck: [:every_push, {:every, :timer.minutes(1)}]

  @impl true
  def join("workspace:" <> _id, _params, socket), do: {:ok, socket}

  defp workspace_id("workspace:" <> id), do: id
end
```

Put `use Warden.Phoenix.Channel` after `use Phoenix.Channel`.

| Option | Meaning |
|---|---|
| `rule:` (required) | The rule the socket's actor must pass to join and to stay joined. |
| `value:` | The guarded value for the rule (`Warden.Check.value`): `fn topic -> ... end` or `fn topic, params -> ... end`, where `params` are the join params. Default: `nil`. |
| `recheck:` | `:every_push`, `{:every, ms}`, a list of both, or `[]` for the join only. Default: `:every_push`. |
| `authorizer:` | The authorizer module. Default: `config :warden, authorizer: MyApp.Authz`. |
| `on_deny:` | `{module, function}`, called as `function(socket, denial)`. Returns the map the client receives. |

The options are checked at compile time. An unknown role, permission or check in the
rule, an unknown option, a missing authorizer, a `value:` that is not a function of
arity 1 or 2, or an `on_deny:` function that does not exist fails compilation.

`value:` runs on every check, so the rule always sees the value as it is now. Keep it
cheap: compute it from the topic and the params.

## When the rule is checked

**At join.** Before your `join/3` runs. A denied join returns `{:error, reply}` to the
client, and your `join/3` does not run.

**`:every_push`.** Before every callback that can send something to the client:

- `handle_out/3`, for every broadcast on the topic;
- your `handle_in/3`, `handle_info/2`, `handle_call/3` and `handle_cast/2`, when you
  define them.

A denied broadcast is dropped and the callback does not run.

Phoenix sends a broadcast straight to the client, past the channel process, for every
event the channel does not intercept. So with `:every_push`, Warden intercepts every
event. Your own `intercept/1` list and `handle_out/3` keep working: an allowed
broadcast of an event you intercept goes to your `handle_out/3`, and any other allowed
broadcast is pushed unchanged. This has the cost that `Phoenix.Channel.intercept/1`
describes: each broadcast is encoded once per subscriber, not once for all.

**`{:every, ms}`.** A timer checks the rule every `ms` milliseconds. A channel that
receives nothing still ends when access ends. The timer message never reaches your
`handle_info/2`.

## What the client sees

A refused join gets the reply map as the join error:

```javascript
channel.join()
  .receive("error", ({reason}) => showError(reason))
```

A denial after the join pushes the event `"warden:denied"` with the reply map, and then
stops the channel with reason `{:shutdown, :forbidden}`:

```javascript
channel.on("warden:denied", ({reason}) => showError(reason))
```

The reply map is `%{reason: "unauthorized"}` for an anonymous actor and
`%{reason: "forbidden"}` for everyone else. It never holds the subject or the guarded
value. To send something else, return a map from `on_deny:`. The handler cannot keep a
denied channel open: Warden stops the channel whatever it returns, and a return value
that is not a map gets the default reply.

Warden does not wrap your `terminate/2`. After a denial Phoenix calls it with reason
`{:shutdown, :forbidden}`; it must not push anything (match on that reason if it
pushes in other cases), because the actor no longer has access.

## The actor

There is no cache. Every check builds the actor from the socket as it is now:

1. `c:Warden.Authorizer.socket_context/1` returns the context. The default is
   `socket.assigns`.
2. `subject/1`, `roles/2` and `permissions/2` run on that context.

So an assign that your callback changes is seen by the next check, and a role or a
membership that is revoked in your data is seen by the next push. Keep those callbacks
cheap, because they run on every push.

```elixir
defmodule MyApp.Authz do
  use Warden.Authorizer, roles: [:member], checks: [:workspace_member]

  @impl true
  def socket_context(socket), do: Map.put(socket.assigns, :transport, :channel)

  # subject/1, roles/2, check/2 ...
end
```

## How your callbacks are wrapped

`use Warden.Phoenix.Channel` adds a `@before_compile` hook. The hook marks your `join/3`
(and, with `:every_push`, your `handle_out/3`, `handle_in/3`, `handle_info/2`,
`handle_call/3` and `handle_cast/2`) as overridable with `defoverridable`. It then
defines a function with the same name that checks the rule first and calls yours with
`super`. Define your callbacks as usual, with any clauses, anywhere in the module.

## By hand

For a channel without `use Warden.Phoenix.Channel`, or for an extra rule on one message:

```elixir
def join("workspace:" <> id, _params, socket) do
  Warden.Phoenix.Channel.authorize_join(socket, check(:workspace_member), value: id)
end

def handle_in("rename", params, socket) do
  case Warden.Phoenix.Channel.authorize(socket, role(:admin)) do
    {:ok, socket} -> {:reply, :ok, rename(socket, params)}
    {:error, _denial} -> {:reply, {:error, %{reason: "forbidden"}}, socket}
  end
end
```

- `authorize_join/3` returns `{:ok, socket}` or `{:error, reply}`, the shape `join/3`
  returns.
- `authorize/3` returns `{:ok, socket}` or `{:error, %Warden.Denial{}}` and sends
  nothing.
- `actor/2` builds the actor for the socket now, to pass to the core API.

These check once, when you call them. They start no rechecks.
