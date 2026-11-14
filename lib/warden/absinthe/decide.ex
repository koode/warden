# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Decide do
    @moduledoc false
    # The first pass of the post middleware: decides the object rules for every value a
    # field returned, before the second pass (the walk in `Warden.Absinthe.Middleware`)
    # applies list policies, null folding and item errors.
    #
    # Deciding all values first lets batched checks see a whole list at once: the values
    # are collected in walk order (depth first, left to right, `nil` skipped), grouped by
    # the rule that applies to them, and each group is evaluated with
    # `Warden.Evaluator.many/3`, which calls each batched check once per group. The
    # result is the value tree with every checked position wrapped as
    # `{@decided, value, :ok | {:deny, denial}}`; the walk reads the outcome from there.
    #
    # For abstract types the abstract type's rule is decided first; the concrete type's
    # rule only for the values that passed it, as before batching. A value whose concrete
    # type cannot be determined is denied (fail closed).

    alias Absinthe.Resolution
    alias Warden.Absinthe.Middleware
    alias Warden.{Check, Denial, Evaluator}

    @decided :__warden_decided__
    @undetermined %{failed_rule: :deny, missing_roles: [], missing_permissions: []}

    # Returns {decided_value, actor, %{count: n, denied: d, reason: first_reason}}.
    def decide(value, spec, ctx) do
      values = value |> flatten(spec.shape, []) |> Enum.reverse()
      {outcomes, actor} = decide_values(values, spec, ctx)
      {decided, []} = rebuild(value, spec.shape, outcomes)
      denials = for {:deny, denial} <- outcomes, do: denial

      stats = %{
        count: length(values),
        denied: length(denials),
        reason: first_reason(denials),
        admitted: admitted(values, outcomes, spec, ctx)
      }

      {decided, actor, stats}
    end

    # The values admitted by a batched object rule of a plain object type. Their fields'
    # pre middleware does not decide that rule again for them (see `Middleware.pre/2`),
    # so a list stays one batched call instead of one call per value and field.
    defp admitted(values, outcomes, %{abstract: nil} = spec, ctx) do
      rule = Map.get(spec.rules, spec.named)

      if rule != nil and Evaluator.batched?(rule, ctx.spec.authorizer.__warden_catalog__()) do
        for {value, :ok} <- Enum.zip(values, outcomes), do: {spec.named, value}
      else
        []
      end
    end

    defp admitted(_values, _outcomes, _spec, _ctx), do: []

    defp first_reason([%Denial{reason: reason} | _rest]), do: reason
    defp first_reason([]), do: nil

    # The checked values, in reverse walk order.
    defp flatten(nil, _shape, acc), do: acc
    defp flatten(value, {:non_null, inner}, acc), do: flatten(value, inner, acc)

    defp flatten(values, {:list, inner}, acc) when is_list(values),
      do: Enum.reduce(values, acc, &flatten(&1, inner, &2))

    # A non-list value for a list type: Absinthe wraps it with List.wrap/1.
    defp flatten(value, {:list, inner}, acc), do: flatten([value], {:list, inner}, acc)
    defp flatten(value, :named, acc), do: [value | acc]

    # Wraps every checked position with its outcome; returns {value, rest_outcomes}.
    defp rebuild(nil, _shape, outcomes), do: {nil, outcomes}
    defp rebuild(value, {:non_null, inner}, outcomes), do: rebuild(value, inner, outcomes)

    defp rebuild(values, {:list, inner}, outcomes) when is_list(values),
      do: Enum.map_reduce(values, outcomes, &rebuild(&1, inner, &2))

    defp rebuild(value, {:list, inner}, outcomes), do: rebuild([value], {:list, inner}, outcomes)

    defp rebuild(value, :named, [outcome | rest]) do
      decided = {@decided, value, outcome}
      {decided, rest}
    end

    defp decide_values([], _spec, ctx), do: {[], ctx.actor}

    defp decide_values(values, %{abstract: nil} = spec, ctx) do
      decide_group(Map.get(spec.rules, spec.named), spec.named, values, ctx)
    end

    defp decide_values(values, spec, ctx) do
      {abstract, actor} = decide_group(spec.abstract_rule, spec.named, values, ctx)
      ctx = %{ctx | actor: actor}

      passed =
        for {{value, :ok}, index} <- values |> Enum.zip(abstract) |> Enum.with_index(),
            do: {index, value}

      {concrete, actor} = decide_concrete(passed, spec, ctx)
      outcomes = abstract |> Enum.with_index() |> Enum.map(&merge_concrete(&1, concrete))
      {outcomes, actor}
    end

    defp merge_concrete({:ok, index}, concrete), do: Map.fetch!(concrete, index)
    defp merge_concrete({denied, _index}, _concrete), do: denied

    # Returns {%{index => outcome}, actor}.
    defp decide_concrete(passed, %{rules: rules}, ctx) when map_size(rules) == 0,
      do: {Map.new(passed, fn {index, _value} -> {index, :ok} end), ctx.actor}

    defp decide_concrete(passed, spec, ctx) do
      groups =
        Enum.group_by(
          passed,
          fn {_index, value} ->
            Middleware.resolve_concrete(spec.abstract, spec.named, value, ctx.res)
          end
        )

      Enum.reduce(groups, {%{}, ctx.actor}, fn {concrete, members}, {acc, actor} ->
        {indexes, values} = Enum.unzip(members)
        {outcomes, actor} = decide_concrete_group(concrete, values, spec, %{ctx | actor: actor})
        decided = indexes |> Enum.zip(outcomes) |> Map.new()
        {Map.merge(acc, decided), actor}
      end)
    end

    defp decide_concrete_group(nil, values, spec, ctx) do
      denial = denial(:deny, @undetermined, spec.named, ctx)
      {Enum.map(values, fn _value -> {:deny, denial} end), ctx.actor}
    end

    defp decide_concrete_group(concrete, values, spec, ctx),
      do: decide_group(Map.get(spec.rules, concrete), concrete, values, ctx)

    # One rule over a group of values. Returns {outcomes, actor}.
    defp decide_group(nil, _type, values, ctx),
      do: {Enum.map(values, fn _value -> :ok end), ctx.actor}

    defp decide_group(rule, type, values, ctx) do
      %Check{} = base = ctx.base
      checks = Enum.map(values, &%{base | actor: ctx.actor, value: &1, type: type})
      {results, actor} = Evaluator.many(rule, checks, ctx.spec.authorizer)
      ctx = %{ctx | actor: actor}
      outcomes = Enum.map(results, &outcome(&1, rule, type, ctx))
      {outcomes, actor}
    end

    # Turns an evaluation result into the outcome the walk reads.
    def outcome(:ok, _rule, _type, _ctx), do: :ok
    def outcome({:deny, failure}, rule, type, ctx), do: {:deny, denial(rule, failure, type, ctx)}

    defp denial(rule, failure, type, ctx) do
      %Denial{
        kind: :object,
        rule: rule,
        failed_rule: failure.failed_rule,
        missing_roles: failure.missing_roles,
        missing_permissions: failure.missing_permissions,
        reason: Map.get(failure, :reason),
        trace: Map.get(failure, :trace, []),
        actor: ctx.actor,
        path: Resolution.path(ctx.res),
        field: ctx.base.field,
        parent_type: ctx.base.parent_type,
        type: type
      }
    end
  end
end
