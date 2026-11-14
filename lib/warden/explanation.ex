defmodule Warden.Explanation do
  @moduledoc """
  The full evaluation of a rule, from `Warden.explain/3`. Meant for development tools,
  tests and audit logs, not for every request: it evaluates every sub-rule, without
  short-circuiting, so every check runs.

    * `result` - `:ok` or `:deny`. Always the same decision as `Warden.authorize/3`.
    * `reason` - the reason of the denial, as in `Warden.Denial.reason`.
    * `steps` - the evaluation tree: `[%{rule: rule, result: :ok | {:deny, reason},
      steps: [...]}]`, with rule terms only, never values.
    * `delegator` - for a delegated actor, the explanation for the delegator (the
      decision is the AND of both), else `nil`.
  """

  @type step :: %{rule: Warden.Rule.t(), result: :ok | {:deny, term}, steps: [step]}

  @type t :: %__MODULE__{
          result: :ok | :deny,
          reason: term,
          steps: [step],
          delegator: t | nil
        }

  defstruct result: :deny, reason: nil, steps: [], delegator: nil
end
