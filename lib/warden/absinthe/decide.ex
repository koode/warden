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
    #
    # Then `redact_with`: every value that passed is replaced by its redacted struct,
    # decided per field policy for the whole group (`Warden.Fields.Redactor`), so the
    # walk, and every child field after it, sees the redacted value.

    alias Absinthe.Resolution
    alias Warden.Absinthe.Middleware
    alias Warden.{Check, Denial, Evaluator}
    alias Warden.Fields.Redactor

    @decided :__warden_decided__
    @undetermined %{failed_rule: :deny, missing_roles: [], missing_permissions: []}

    # Returns {decided_value, actor, %{count: n, denied: d, reason: first_reason}}.
    def decide(value, spec, ctx) do
      values = value |> flatten(spec.shape, []) |> Enum.reverse()
      {outcomes, types, actor} = decide_values(values, spec, ctx)
      {values, actor} = redact(values, outcomes, types, spec, %{ctx | actor: actor})
      outcomes = same_type_after_redaction(values, outcomes, types, spec, %{ctx | actor: actor})
      admits = admits(outcomes, types, spec, ctx)
      {decided, []} = rebuild(value, spec.shape, Enum.zip([values, outcomes, admits]))
      denials = for {:deny, denial} <- outcomes, do: denial

      stats = %{
        count: length(values),
        denied: length(denials),
        reason: first_reason(denials)
      }

      {decided, actor, stats}
    end

    # The type under which a passing value is admitted, or nil: the fields' pre
    # middleware does not decide that type's object rule again for it (see
    # `Middleware.pre/2`). Admitted are values of a type whose object rule is batched, so
    # a list stays one batched call instead of one call per value and field, and every
    # redacted value: its object rule was decided on the value before redaction, and
    # deciding it again on the redacted struct could disagree. For abstract types the
    # concrete type counts. `Plan.admissible?/3` is the same test, for the pre specs.
    defp admits(outcomes, types, spec, ctx) do
      catalog = ctx.spec.authorizer.__warden_catalog__()

      outcomes
      |> Enum.with_index()
      |> Enum.map(fn {outcome, index} ->
        type = value_type(index, types, spec)

        if outcome == :ok and admissible?(type, spec, catalog), do: type, else: nil
      end)
    end

    defp admissible?(nil, _spec, _catalog), do: false

    defp admissible?(type, spec, catalog) do
      rule = Map.get(spec.rules, type)

      rule != nil and
        (Map.has_key?(redactors(spec), type) or Evaluator.batched?(rule, catalog))
    end

    defp redactors(spec), do: Map.get(spec, :redactors, %{})

    # Replaces every value that passed with its redacted struct. Returns {values, actor}.
    defp redact(values, outcomes, types, spec, ctx) do
      redactors = redactors(spec)

      if map_size(redactors) == 0 do
        {values, ctx.actor}
      else
        groups =
          for {{value, :ok}, index} <- values |> Enum.zip(outcomes) |> Enum.with_index(),
              module = Map.get(redactors, value_type(index, types, spec)),
              module != nil do
            {module, index, value}
          end
          |> Enum.group_by(&elem(&1, 0), fn {_module, index, value} -> {index, value} end)

        {replaced, actor} = Enum.reduce(groups, {%{}, ctx.actor}, &redact_group(&1, &2, ctx))
        redacted = values |> Enum.with_index() |> Enum.map(&replaced_value(&1, replaced))
        {redacted, actor}
      end
    end

    # Absinthe resolves the concrete type of an abstract value again, on the value the
    # walk hands it: the redacted one. When redaction changed what `resolve_type` reads,
    # the value would run as a type whose rules were not decided for it, so it is denied.
    # The type is never pinned to the one decided.
    defp same_type_after_redaction(_values, outcomes, _types, %{abstract: nil}, _ctx),
      do: outcomes

    defp same_type_after_redaction(values, outcomes, types, spec, ctx) do
      redactors = redactors(spec)

      [values, outcomes]
      |> Enum.zip()
      |> Enum.with_index()
      |> Enum.map(fn {{value, outcome}, index} ->
        type = Map.get(types, index)

        if outcome == :ok and Map.has_key?(redactors, type) and
             Middleware.resolve_concrete(spec.abstract, spec.named, value, ctx.res) != type,
           do: {:deny, denial(:deny, @undetermined, type, ctx)},
           else: outcome
      end)
    end

    defp value_type(_index, _types, %{abstract: nil} = spec), do: spec.named
    defp value_type(index, types, _spec), do: Map.get(types, index)

    defp redact_group({module, members}, {replaced, actor}, ctx) do
      {indexes, values} = Enum.unzip(members)
      authorizer = ctx.spec.authorizer

      {redacted, actor} =
        Redactor.redact_group(module, values, actor, ctx.base.context, authorizer)

      replaced = indexes |> Enum.zip(redacted) |> Map.new() |> Map.merge(replaced)
      {replaced, actor}
    end

    defp replaced_value({value, index}, replaced), do: Map.get(replaced, index, value)

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

    # Wraps every checked position with its (possibly redacted) value and outcome;
    # returns {value, rest_entries}.
    defp rebuild(nil, _shape, entries), do: {nil, entries}
    defp rebuild(value, {:non_null, inner}, entries), do: rebuild(value, inner, entries)

    defp rebuild(values, {:list, inner}, entries) when is_list(values),
      do: Enum.map_reduce(values, entries, &rebuild(&1, inner, &2))

    defp rebuild(value, {:list, inner}, entries), do: rebuild([value], {:list, inner}, entries)

    defp rebuild(_value, :named, [{value, outcome, admit} | rest]) do
      decided = {@decided, value, outcome, admit}
      {decided, rest}
    end

    # Returns {outcomes, %{index => concrete_type}, actor}; the concrete types are only
    # known for abstract types.
    defp decide_values([], _spec, ctx), do: {[], %{}, ctx.actor}

    defp decide_values(values, %{abstract: nil} = spec, ctx) do
      {outcomes, actor} = decide_group(Map.get(spec.rules, spec.named), spec.named, values, ctx)
      {outcomes, %{}, actor}
    end

    defp decide_values(values, spec, ctx) do
      {abstract, actor} = decide_group(spec.abstract_rule, spec.named, values, ctx)
      ctx = %{ctx | actor: actor}

      passed =
        for {{value, :ok}, index} <- values |> Enum.zip(abstract) |> Enum.with_index(),
            do: {index, value}

      {concrete, types, actor} = decide_concrete(passed, spec, ctx)
      outcomes = abstract |> Enum.with_index() |> Enum.map(&merge_concrete(&1, concrete))
      {outcomes, types, actor}
    end

    defp merge_concrete({:ok, index}, concrete), do: Map.fetch!(concrete, index)
    defp merge_concrete({denied, _index}, _concrete), do: denied

    # Returns {%{index => outcome}, %{index => concrete_type}, actor}. The concrete type is
    # resolved when an object rule or a field policy may apply.
    defp decide_concrete(passed, %{rules: rules} = spec, ctx)
         when map_size(rules) == 0 and not is_map_key(spec, :redactors),
         do: {Map.new(passed, fn {index, _value} -> {index, :ok} end), %{}, ctx.actor}

    defp decide_concrete(passed, spec, ctx) do
      groups =
        Enum.group_by(
          passed,
          fn {_index, value} ->
            Middleware.resolve_concrete(spec.abstract, spec.named, value, ctx.res)
          end
        )

      Enum.reduce(groups, {%{}, %{}, ctx.actor}, fn {concrete, members}, {acc, types, actor} ->
        {indexes, values} = Enum.unzip(members)
        {outcomes, actor} = decide_concrete_group(concrete, values, spec, %{ctx | actor: actor})
        decided = indexes |> Enum.zip(outcomes) |> Map.new()
        typed = Map.new(indexes, &{&1, concrete})
        {Map.merge(acc, decided), Map.merge(types, typed), actor}
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
