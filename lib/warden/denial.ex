defmodule Warden.Denial do
  @moduledoc """
  Describes a denied authorization, passed to `c:Warden.Authorizer.deny/1`.

    * `kind`: `:field | :object | :argument | :subscribe | :introspection` (GraphQL),
      `:call` (the core API and `Warden.Plug`).
    * `rule`: the rule that was evaluated. `failed_rule`: the sub-rule that failed.
    * `missing_roles` / `missing_permissions`: what the actor lacked, as far as it can be
      computed (empty for `check` and `authenticated` failures).
    * `path`: the response path of the field.
    * `field` / `parent_type`: identifiers of the field and the type that owns it.
    * `type`: for object denials, the identifier of the denied object type.
    * `value_index`: for denied list items, the index path inside the list (a list of
      integers, one per list level), else `nil`.
    * `argument`: for argument denials, the argument or input field path.
    * `list_policy`: for denied list items, the policy in effect (`:null_item`, `:filter`,
      `:fail_list`), else `nil`.
    * `reason`: why the failing check or policy denied (`{:deny, reason}`), `:unavailable`
      for a check that timed out, a list in rule order for `any_of`, else `nil`.
    * `trace`: `[{rule, :ok | {:deny, reason}}]`, every leaf rule evaluated, in order.
      Rule terms only, never values.

  `inspect/1` shows the kind, the rules, what was missing, the reason (atoms only: the
  map of a `{atom, map}` reason is left out), the path and the types. Never the actor,
  the guarded value or the trace.
  """

  @typedoc "Why a check or policy denied: an atom, or an atom with details."
  @type reason :: atom | {atom, map}

  @type kind :: :field | :object | :argument | :subscribe | :introspection | :call

  @type t :: %__MODULE__{
          kind: kind,
          rule: Warden.Rule.t(),
          failed_rule: Warden.Rule.t(),
          missing_roles: [atom],
          missing_permissions: [term],
          actor: Warden.Actor.t() | nil,
          path: [String.t() | non_neg_integer],
          field: atom | nil,
          parent_type: atom | nil,
          type: atom | nil,
          value_index: nil | [non_neg_integer],
          argument: nil | [atom | non_neg_integer],
          list_policy: nil | Warden.Rule.list_policy(),
          reason: reason | [term] | nil,
          trace: [{Warden.Rule.t(), :ok | {:deny, term}}]
        }

  defstruct [
    :kind,
    :rule,
    :failed_rule,
    :actor,
    :field,
    :parent_type,
    :type,
    :value_index,
    :argument,
    :list_policy,
    :reason,
    trace: [],
    missing_roles: [],
    missing_permissions: [],
    path: []
  ]
end

defimpl Inspect, for: Warden.Denial do
  # The actor (and its subject, the user record), the guarded value and the rule's
  # argument data stay out of inspect output; the fields are still available to code.
  import Inspect.Algebra

  def inspect(denial, opts) do
    fields = [
      kind: denial.kind,
      failed_rule: denial.failed_rule,
      missing_roles: denial.missing_roles,
      missing_permissions: denial.missing_permissions,
      reason: Warden.Telemetry.public_reason(denial.reason),
      path: denial.path,
      field: denial.field,
      parent_type: denial.parent_type,
      type: denial.type
    ]

    concat(["#Warden.Denial<", to_doc(fields, opts), ">"])
  end
end
