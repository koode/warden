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

  `inspect/1` shows reasons as `Warden.Denial` does: atoms only, never the map of an
  `{atom, map}` reason, in every step too. The fields keep the full reasons.
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

defimpl Inspect, for: Warden.Explanation do
  # Explanations end up in logs and audit records. Reasons go through the same filter as
  # `Warden.Denial`'s inspect: atoms only, never the map of an `{atom, map}` reason, in
  # every step too.
  import Inspect.Algebra

  alias Warden.Telemetry

  def inspect(explanation, opts) do
    fields = [
      result: explanation.result,
      reason: Telemetry.public_reason(explanation.reason),
      steps: Enum.map(explanation.steps, &public_step/1),
      delegator: explanation.delegator
    ]

    concat(["#Warden.Explanation<", to_doc(fields, opts), ">"])
  end

  defp public_step(%{rule: rule, result: result, steps: steps}) do
    %{rule: rule, result: public_result(result), steps: Enum.map(steps, &public_step/1)}
  end

  defp public_result({:deny, reason}), do: {:deny, Telemetry.public_reason(reason)}
  defp public_result(result), do: result
end
