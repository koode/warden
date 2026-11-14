# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Audience do
    @moduledoc false
    # `Warden.Ecto.allowed_actors/4`: one row, many actors, one query. Each actor is
    # decided like a single check (gates, a hand-written `allowed?/4`, the clauses in
    # memory); the actors that need the database get their scope as one column of a
    # single `SELECT` of the row.

    import Ecto.Query, only: [from: 2]

    alias Warden.{Actor, Decision, Rule, Telemetry}
    alias Warden.Ecto.{Decide, Info, Memory, Scope}
    alias Warden.Ecto.Policy.Graph

    @spec allowed_actors([term], atom, term, keyword) :: [term]
    def allowed_actors(actors, action, row, opts) do
      decided =
        actors
        |> Enum.with_index()
        |> Enum.map(fn {element, index} -> decide(element, index, action, row, opts) end)

      columns =
        for {_element, _actor, _info, %Ecto.Query.DynamicExpr{} = verdict, index} <- decided,
            into: %{},
            do: {index, verdict}

      selected = select_row(decided, row, columns)

      results =
        Enum.map(decided, fn {element, actor, info, verdict, index} ->
          passed = verdict == true or Map.get(selected, index) == true
          emit(info, action, actor, passed)
          {element, passed}
        end)

      for {element, true} <- results, do: element
    end

    defp decide(element, index, action, row, opts) do
      {actor, context, authorizer} = Decision.setup(element, opts)
      info = Info.policy_for!(authorizer, row_schema(row))
      Info.ensure_action!(info, action)
      Graph.ensure_valid!(info.policy)
      {verdict, actor} = verdict(info, action, actor, row, Scope.new(context, Info.prefix(row)))
      {element, actor, info, verdict, index}
    end

    # `{schema, id}`: the scope over every tenant of the actor.
    defp verdict(info, action, actor, {_schema, _id}, state) do
      {verdict, actor, _state} = Scope.scope(info, action, actor, :all, state)
      {verdict, actor}
    end

    # A loaded struct: each side decided like a single check, then ANDed.
    defp verdict(info, action, %Actor{delegator: nil} = actor, struct, state) do
      {verdict, actor, _state} = side(info, action, actor, actor, struct, state)
      {verdict, actor}
    end

    defp verdict(info, action, %Actor{delegator: delegator} = actor, struct, state) do
      {own, side, state} = side(info, action, %{actor | delegator: nil}, actor, struct, state)
      {theirs, delegator, _state} = side(info, action, delegator, delegator, struct, state)
      {Scope.both(own, theirs), %{side | delegator: delegator}}
    end

    # `asked` is the actor a hand-written `allowed?/4` is asked about (the full actor
    # for the first side, as the evaluator does).
    defp side(info, action, side, asked, struct, state) do
      tenant = Memory.tenant(info, struct)
      {gate, state} = Scope.gate(info, side, tenant, state)

      cond do
        gate != nil or Map.get(struct, info.primary_key) == nil ->
          {false, side, state}

        info.allowed? or info.allowed_many? ->
          {custom(info, action, asked, struct, state.context), side, state}

        true ->
          planned(info, action, side, tenant, struct, state)
      end
    end

    defp planned(info, action, side, tenant, struct, state) do
      case Memory.decide(info, action, side, struct, state) do
        {:unknown, side, state} ->
          {verdict, side, state} = Scope.verdict(info, action, side, tenant, state)
          {Scope.both(Scope.tenant_condition(info, tenant), verdict), side, state}

        decided ->
          decided
      end
    end

    defp custom(info, action, actor, struct, context) do
      [answer] =
        if info.allowed?,
          do: [info.policy.allowed?(action, actor, struct, context)],
          else: Decide.many!(info, action, actor, [struct], context)

      Warden.Evaluator.verdict!(answer, info.policy, action) == :ok
    end

    defp select_row(_decided, _row, columns) when columns == %{}, do: %{}

    defp select_row([{_element, _actor, info, _verdict, _index} | _rest], row, columns) do
      case row_key(info, row) do
        nil -> %{}
        key -> info |> row_query(key, columns) |> Map.put(:prefix, Info.prefix(row)) |> run(info)
      end
    end

    defp row_query(info, key, columns) do
      primary_key = info.primary_key

      from(row in info.schema,
        as: ^info.as,
        where: field(row, ^primary_key) == ^key,
        select: ^columns
      )
    end

    defp run(query, info) do
      repo = Info.repo!(info)
      repo.one(query) || %{}
    end

    defp row_key(info, {_schema, id}) do
      case Ecto.Type.cast(info.primary_key_type, id) do
        {:ok, key} -> key
        :error -> nil
      end
    end

    defp row_key(info, struct), do: Map.get(struct, info.primary_key)

    defp row_schema(%schema{}), do: schema
    defp row_schema({schema, _id}), do: schema

    defp emit(info, action, actor, passed) do
      decision = %{
        layer: :ecto,
        kind: :call,
        rule: Rule.can(info.policy, action),
        actor: actor,
        count: 1,
        denied: if(passed, do: 0, else: 1)
      }

      Telemetry.decision(decision)
    end
  end
end
