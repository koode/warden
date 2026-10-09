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
  """

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
          list_policy: nil | Warden.Rule.list_policy()
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
    missing_roles: [],
    missing_permissions: [],
    path: []
  ]
end
