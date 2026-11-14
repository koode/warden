# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Explain do
    @moduledoc false
    # `Warden.Ecto.explain/4`: every clause and every key of it, evaluated for one row
    # against the database without short-circuiting, in one query per actor side (each
    # part's dynamic is one selected column).

    import Ecto.Query, only: [from: 2]

    alias Warden.{Actor, Explanation}
    alias Warden.Ecto.{Info, Memory, Scope}

    @spec explain(map, atom, Actor.t(), term, map) :: Explanation.t()
    def explain(info, action, %Actor{} = actor, row, context) do
      Info.ensure_action!(info, action)

      case locate(info, row) do
        {:ok, key, tenant} ->
          state = Scope.new(context)
          own = side(info, action, %{actor | delegator: nil}, key, tenant, state)
          delegator = actor.delegator && side(info, action, actor.delegator, key, tenant, state)

          result =
            if own.result == :ok and (delegator == nil or delegator.result == :ok),
              do: :ok,
              else: :deny

          %{own | result: result, delegator: delegator}

        :missing ->
          gate(:no_row)
      end
    end

    # The row's key and tenant: from a loaded struct, or read for `{schema, id}`.
    defp locate(info, {_schema, id}) do
      with {:ok, key} when key != nil <- Ecto.Type.cast(info.primary_key_type, id),
           {:ok, tenant} <- read_tenant(info, key) do
        {:ok, {nil, key}, tenant}
      else
        _missing -> :missing
      end
    end

    defp locate(info, struct) do
      case Map.get(struct, info.primary_key) do
        nil -> :missing
        key -> {:ok, {Info.prefix(struct), key}, Memory.tenant(info, struct)}
      end
    end

    defp read_tenant(info, key) do
      primary_key = info.primary_key
      selected = if info.tenant == nil, do: primary_key, else: info.tenant

      query =
        from(row in info.schema,
          where: field(row, ^primary_key) == ^key,
          select: {field(row, ^selected)}
        )

      repo = Info.repo!(info)

      case repo.one(query) do
        nil -> :missing
        {tenant} when info.tenant != nil -> {:ok, tenant}
        {_key} -> {:ok, nil}
      end
    end

    defp side(info, action, side, key, tenant, state) do
      case Scope.gate(info, side, tenant, state) do
        {nil, state} -> planned(info, action, side, key, tenant, state)
        {reason, _state} -> gate(reason)
      end
    end

    defp gate(reason) do
      step = %{rule: {:gate, reason}, result: {:deny, reason}, steps: []}
      %Explanation{result: :deny, reason: reason, steps: [step]}
    end

    defp planned(info, action, side, key, tenant, state) do
      case Map.fetch!(info.actions, action) do
        :scope ->
          {verdict, _side, _state} = Scope.verdict(info, action, side, tenant, state)
          [passed] = evaluate(info, key, tenant, [verdict])
          step = %{rule: {:scope, action}, result: outcome(passed), steps: []}
          %Explanation{result: result(passed), steps: [step]}

        {:clauses, requires, allows} ->
          clauses(info, side, key, tenant, requires, allows, state)
      end
    end

    defp clauses(info, side, key, tenant, requires, allows, state) do
      applicable = Scope.applicable(allows, side)
      clauses = requires ++ allows

      {verdicts, _acc} =
        Enum.map_reduce(clauses, {side, state}, fn clause, {side, state} ->
          {parts, side, state} = part_verdicts(info, clause, side, tenant, state)
          {{clause, parts}, {side, state}}
        end)

      flat = for {_clause, parts} <- verdicts, {_part, verdict} <- parts, do: verdict
      answers = evaluate(info, key, tenant, flat)
      {steps, _answers} = Enum.map_reduce(verdicts, answers, &clause_step(&1, &2, applicable))

      required = steps |> Enum.take(length(requires)) |> Enum.all?(&(&1.result == :ok))
      allowed = steps |> Enum.drop(length(requires)) |> Enum.any?(&(&1.result == :ok))
      passed = required and allowed
      %Explanation{result: result(passed), steps: steps}
    end

    defp part_verdicts(info, clause, side, tenant, state) do
      Enum.reduce(clause.parts, {[], side, state}, fn part, {parts, side, state} ->
        {verdict, side, state} = Scope.part(info, clause, part, side, tenant, state)
        {parts ++ [{part, verdict}], side, state}
      end)
    end

    defp clause_step({clause, parts}, answers, applicable) do
      {part_steps, answers} =
        Enum.map_reduce(parts, answers, fn {part, _verdict}, [passed | answers] ->
          {%{rule: part, result: outcome(passed), steps: []}, answers}
        end)

      passed = Enum.all?(part_steps, &(&1.result == :ok))
      skipped? = clause.kind == :allow and clause not in applicable
      result = if skipped?, do: {:deny, :system_kind}, else: outcome(passed)
      kind = if clause.kind == :allow, do: :allow, else: :requires
      step = %{rule: {kind, clause.action, clause.index}, result: result, steps: part_steps}
      {step, answers}
    end

    # Evaluates verdicts for the row in one query: static ones as they are, dynamic ones
    # as selected columns. A row that is not in the tenant makes every dynamic `false`.
    defp evaluate(info, key, tenant, verdicts) do
      columns =
        for {%Ecto.Query.DynamicExpr{} = verdict, index} <- Enum.with_index(verdicts),
            into: %{},
            do: {index, verdict}

      selected = if columns == %{}, do: %{}, else: select(info, key, tenant, columns)

      verdicts
      |> Enum.with_index()
      |> Enum.map(fn
        {verdict, _index} when is_boolean(verdict) -> verdict
        {_verdict, index} -> Map.get(selected, index) == true
      end)
    end

    # A struct loaded from another query prefix is explained against that prefix.
    defp select(info, {prefix, key}, tenant, columns) do
      primary_key = info.primary_key

      query =
        from(row in info.schema,
          as: ^info.as,
          where: field(row, ^primary_key) == ^key,
          select: ^columns
        )

      query = Scope.restrict(query, Scope.tenant_condition(info, tenant))
      query = %{query | prefix: prefix}
      repo = Info.repo!(info)
      repo.one(query) || %{}
    end

    defp outcome(true), do: :ok
    defp outcome(false), do: {:deny, nil}

    defp result(true), do: :ok
    defp result(false), do: :deny
  end
end
