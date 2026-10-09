defmodule Warden do
  @moduledoc """
  Role- and permission-based authorization for Absinthe.

  Rules attach to fields, object types, interfaces, unions, arguments and input fields.
  Denied data becomes `null` (folded to the nearest nullable parent); the request does
  not fail as a whole. Queries, mutations and subscriptions are enforced the same way.

    * `Warden.Authorizer` - the behaviour for your authorizer module (catalogs,
      callbacks).
    * `Warden.Absinthe` - `use` it in your schema to enable Warden.
    * `Warden.Absinthe.Notation` - `authorize/1`, `authorize_args/1`, `list_policy/1`.
    * `Warden.Rule` - the rule builders and evaluator.
    * `Warden.Absinthe.Hydrate` - rules for SDL schemas.

  See the README for the security model and its limits.
  """

  @doc """
  Evaluates `rule` for the actor built from `context` by `authorizer`, outside of a
  GraphQL execution. `value` is passed to checks as `Warden.Check.value`.

  Returns `:ok` or `{:deny, failure}`.
  """
  @spec authorize(module, Warden.Rule.t(), map, term) :: :ok | {:deny, Warden.Rule.failure()}
  def authorize(authorizer, rule, context, value \\ nil) do
    actor = Warden.Actor.build(authorizer, context)
    check = %Warden.Check{actor: actor, value: value, context: context}
    Warden.Rule.evaluate(rule, check, authorizer)
  end
end
