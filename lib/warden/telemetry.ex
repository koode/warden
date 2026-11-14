defmodule Warden.Telemetry do
  @moduledoc """
  Warden emits one `[:warden, :decision]` event per decision call.

    * Measurements: `%{count: n, denied: d}`, the number of values decided and how many of
      them were denied. A list (`Warden.filter/4`, a GraphQL list) is one event.
    * Metadata: `%{layer, kind, rule, result, reason, actor_kind, tenant}`.
      * `layer` - `:core`, `:plug`, `:absinthe`, `:channel` or `:fields` (later
        layers add their own). Redaction (`Warden.redact/3`, `redact_with`) reports `:fields`, one event
        per redaction rule and group of structs.
      * `kind` - the denial kind: `:call`, `:field`, `:object`, `:argument`, `:subscribe`
        or `:introspection`. Redaction reports `:field`.
      * `rule` - the rule term.
      * `result` - `:ok` when every value passed, else `:deny`.
      * `reason` - the reason of the (first) denial, reduced to atoms: `{atom, map}`
        becomes `atom`, lists keep their atoms.
      * `actor_kind` - `Warden.Actor.kind/1`.
      * `tenant` - the tenant the decision was about when the rule resolved one, else the
        tenant the actor is bound to, else `nil`.

  The metadata never holds the subject or the guarded value.

      :telemetry.attach("log-denials", [:warden, :decision], &MyApp.log_denial/4, nil)
  """

  alias Warden.Actor

  @event [:warden, :decision]

  @doc "The event name, `[:warden, :decision]`."
  @spec event() :: [atom]
  def event, do: @event

  @doc """
  Emits one decision event. Warden's layers call it; a layer outside Warden (an adapter
  of your own) may too, with `layer`, `kind`, `rule` and `actor`, and optionally
  `count`, `denied`, `reason` and `tenant`.
  """
  @spec decision(map) :: :ok
  def decision(%{layer: layer, kind: kind, rule: rule, actor: %Actor{} = actor} = decision) do
    count = Map.get(decision, :count, 1)
    denied = Map.get(decision, :denied, 0)
    measurements = %{count: count, denied: denied}

    metadata = %{
      layer: layer,
      kind: kind,
      rule: rule,
      result: if(denied == 0, do: :ok, else: :deny),
      reason: public_reason(Map.get(decision, :reason)),
      actor_kind: Actor.kind(actor),
      tenant: Map.get(decision, :tenant) || Actor.bound_tenant(actor)
    }

    :telemetry.execute(@event, measurements, metadata)
  end

  @doc """
  The part of a denial reason that may leave Warden: the atom of a reason, never the
  details map of an `{atom, map}` reason. Lists (from `any_of`) are reduced element by
  element.
  """
  @spec public_reason(term) :: atom | [term] | nil
  def public_reason(reason) when is_atom(reason), do: reason
  def public_reason({reason, _details}) when is_atom(reason), do: reason
  def public_reason(reasons) when is_list(reasons), do: Enum.map(reasons, &public_reason/1)
  def public_reason(_other), do: nil
end
