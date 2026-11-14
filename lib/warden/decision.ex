defmodule Warden.Decision do
  @moduledoc false
  # The decision calls behind the core API and `Warden.Plug`: actor setup, rule
  # validation, evaluation, the denial and the telemetry event. `layer` names the front
  # end in telemetry.

  alias Warden.{Actor, Check, Denial, Evaluator, Rule, Shape, Telemetry}

  @spec authorize(Warden.actor_or_context(), Rule.t(), keyword, atom) ::
          :ok | {:error, Denial.t()}
  def authorize(actor_or_context, rule, opts, layer) when is_list(opts) do
    {actor, context, authorizer} = setup(actor_or_context, opts)
    validate_rule!(rule, authorizer)
    check = check(actor, context, opts, Keyword.get(opts, :value))
    {result, actor, tenant} = Evaluator.one(rule, check, authorizer)
    denial = denial(result, rule, actor)

    emit(layer, rule, actor, tenant, [denial])

    case denial do
      nil -> :ok
      %Denial{} -> {:error, denial}
    end
  end

  @spec filter(Warden.actor_or_context(), Rule.t(), Enumerable.t(), keyword, atom) :: list
  def filter(actor_or_context, rule, values, opts, layer) when is_list(opts) do
    {actor, context, authorizer} = setup(actor_or_context, opts)
    validate_rule!(rule, authorizer)
    values = Enum.to_list(values)
    checks = Enum.map(values, &check(actor, context, opts, &1))
    {results, evaluated} = Evaluator.many(rule, checks, authorizer)
    actor = evaluated || actor
    denials = Enum.map(results, &denial(&1, rule, actor))

    emit(layer, rule, actor, nil, denials)

    for {value, nil} <- Enum.zip(values, denials), do: value
  end

  @spec explain(Warden.actor_or_context(), Rule.t(), keyword) :: Warden.Explanation.t()
  def explain(actor_or_context, rule, opts) when is_list(opts) do
    {actor, context, authorizer} = setup(actor_or_context, opts)
    validate_rule!(rule, authorizer)
    check = check(actor, context, opts, Keyword.get(opts, :value))
    {explanation, _actor} = Evaluator.explain(rule, check, authorizer)
    explanation
  end

  @spec setup(Warden.actor_or_context(), keyword) :: {Actor.t(), map, module}
  def setup(%Actor{} = actor, opts) do
    authorizer = Warden.resolve_authorizer!(opts[:authorizer], actor)
    {actor, Keyword.get(opts, :context, %{}), authorizer}
  end

  def setup(context, opts) when is_map(context) do
    authorizer = Warden.resolve_authorizer!(opts[:authorizer], nil)
    {Actor.build(authorizer, context), context, authorizer}
  end

  def setup(other, _opts) do
    raise ArgumentError,
          "expected a %Warden.Actor{} or a context map, got: #{Shape.describe(other)}"
  end

  @spec validate_rule!(Rule.t(), module) :: :ok
  def validate_rule!(rule, authorizer) do
    case rule_errors(rule, authorizer) do
      [] ->
        :ok

      errors ->
        raise Warden.PolicyError,
              "invalid rule for #{inspect(authorizer)}: " <> Enum.join(errors, "; ")
    end
  end

  # Catalog errors, plus `covered()`: outside GraphQL no object rule guards anything, so
  # it would be a silent `public()`.
  @spec rule_errors(Rule.t(), module) :: [String.t()]
  def rule_errors(rule, authorizer) do
    errors =
      case Rule.validate(rule, authorizer.__warden_catalog__()) do
        :ok -> []
        {:error, errors} -> errors
      end

    if covered?(rule),
      do:
        errors ++ ["covered() is only meaningful on GraphQL fields of a type with an object rule"],
      else: errors
  end

  defp covered?(:covered), do: true

  defp covered?({tag, rules}) when tag in [:all, :any] and is_list(rules),
    do: Enum.any?(rules, &covered?/1)

  defp covered?(_rule), do: false

  defp check(actor, context, opts, value) do
    args = Keyword.get(opts, :args, %{})

    if not is_map(args),
      do: raise(ArgumentError, "`args:` must be a map, got: #{Shape.describe(args)}")

    %Check{actor: actor, value: value, args: args, context: context}
  end

  @spec denial(:ok | {:deny, map}, Rule.t(), Actor.t()) :: Denial.t() | nil
  def denial(:ok, _rule, _actor), do: nil

  def denial({:deny, failure}, rule, actor) do
    %Denial{
      kind: :call,
      rule: rule,
      failed_rule: failure.failed_rule,
      missing_roles: failure.missing_roles,
      missing_permissions: failure.missing_permissions,
      reason: failure.reason,
      trace: failure.trace,
      actor: actor
    }
  end

  defp emit(layer, rule, actor, tenant, denials) do
    denied = Enum.reject(denials, &is_nil/1)

    decision = %{
      layer: layer,
      kind: :call,
      rule: rule,
      actor: actor,
      tenant: tenant,
      count: length(denials),
      denied: length(denied),
      reason: first_reason(denied)
    }

    Telemetry.decision(decision)
  end

  defp first_reason([%Denial{reason: reason} | _rest]), do: reason
  defp first_reason([]), do: nil
end
