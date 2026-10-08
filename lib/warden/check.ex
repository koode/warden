defmodule Warden.Check do
  @moduledoc """
  The input to `c:Warden.Authorizer.check/2`.

    * `name` and `opts` come from the rule: `check(name, opts)`.
    * `actor` is the `Warden.Actor` being authorized.
    * `value` is the value the rule guards. For a field or argument rule it is the parent
      object (`resolution.source`). For an object rule it is the object itself. For a
      root type rule it is the root value. At subscribe time it is `nil`.
    * `args` holds the field arguments (after variables and defaults).
    * `argument` is the argument or input field path for argument rules, else `nil`.
    * `context` is the Absinthe context.
    * `field`, `parent_type` and `type` are identifiers, when known.
    * `resolution` is the `Absinthe.Resolution` struct, or `nil` at subscribe time.
  """

  @type t :: %__MODULE__{
          name: atom,
          opts: keyword,
          actor: Warden.Actor.t(),
          value: term,
          args: map,
          argument: nil | [atom | non_neg_integer],
          context: map,
          field: atom | nil,
          parent_type: atom | nil,
          type: atom | nil,
          resolution: Absinthe.Resolution.t() | nil
        }

  defstruct [
    :name,
    :actor,
    :value,
    :argument,
    :field,
    :parent_type,
    :type,
    :resolution,
    opts: [],
    args: %{},
    context: %{}
  ]
end
