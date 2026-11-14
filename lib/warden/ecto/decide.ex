# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Decide do
    @moduledoc false
    # `__warden_decide__/4` of every `Warden.Ecto.Policy`: one result per value, in order.
    #
    # `Warden.Policy.Dispatch` has already denied `nil` values and system actors of other
    # kinds. Because the policy sets `enforces_binding: true`, the credential's tenant
    # binding is applied here (by the scope gates). The evaluator asks the actor and its
    # delegator separately and ANDs the answers, so the actor is decided as one side.
    #
    #   * Loaded structs: a hand-written `allowed_many/4` or `allowed?/4` answers;
    #     otherwise the clauses in memory where exact, and one query per tenant for the
    #     rest (`WHERE id = ANY($1) AND tenant = $2 AND scope`).
    #   * `{schema, id}` values: one query over the scope of every tenant of the actor.
    #   * Anything else is denied.

    import Ecto.Query, only: [from: 2]

    alias Warden.Actor
    alias Warden.Ecto.{Info, Memory, Scope}
    alias Warden.Ecto.Policy.Graph

    @spec decide(module, atom, Actor.t(), [term], map) :: [Warden.Policy.result()]
    def decide(policy, action, %Actor{} = actor, values, context) do
      info = Info.fetch!(policy)
      Info.ensure_action!(info, action)
      Graph.ensure_valid!(policy)

      side = %{actor | delegator: nil}
      state = Scope.new(context)

      {sorted, {_side, state}} =
        Enum.map_reduce(values, {side, state}, &sort(info, action, &1, &2))

      custom = custom_answers(info, action, actor, sorted, context)

      {tenant_queries, side, state} =
        tenant_queries(info, action, side, tenant_groups(sorted), state)

      {id_query, _side, _state} = id_query(info, action, side, id_values(sorted), state)

      {allowed_rows, allowed_ids} = run(info, tenant_queries, id_query)
      answer(sorted, custom, allowed_rows, allowed_ids)
    end

    # `{:done, answer}`, `{:custom, struct}`, `{:row, tenant, key}` or `{:id, key}`.
    defp sort(info, action, %schema{} = struct, {side, state}) when schema == info.schema do
      tenant = Memory.tenant(info, struct)
      key = Map.get(struct, info.primary_key)
      {gate, state} = Scope.gate(info, side, tenant, state)

      cond do
        gate != nil ->
          {{:done, false}, {side, state}}

        info.allowed? or info.allowed_many? ->
          {{:custom, struct}, {side, state}}

        key == nil ->
          {{:done, false}, {side, state}}

        true ->
          {answer, side, state} = Memory.decide(info, action, side, struct, state)
          sorted = if answer == :unknown, do: {:row, tenant, key}, else: {:done, answer}
          {sorted, {side, state}}
      end
    end

    defp sort(info, _action, {schema, id}, acc) when schema == info.schema do
      case Ecto.Type.cast(info.primary_key_type, id) do
        {:ok, key} when key != nil -> {{:id, key}, acc}
        _invalid -> {{:done, false}, acc}
      end
    end

    defp sort(_info, _action, _value, acc), do: {{:done, false}, acc}

    # The answers of a hand-written `allowed_many/4` (one call) or `allowed?/4`, in the
    # order of the structs. The full actor goes to user code, as for `Warden.Policy`.
    defp custom_answers(info, action, actor, sorted, context) do
      structs = for {:custom, struct} <- sorted, do: struct

      cond do
        structs == [] -> []
        info.allowed_many? -> many!(info, action, actor, structs, context)
        true -> Enum.map(structs, &info.policy.allowed?(action, actor, &1, context))
      end
    end

    # One answer per struct, or a `Warden.PolicyError`: a longer or shorter list would
    # shift every answer onto another row.
    @spec many!(map, atom, Actor.t(), [struct], map) :: list
    def many!(info, action, actor, structs, context) do
      answers = info.policy.allowed_many(action, actor, structs, context)
      expected = length(structs)

      if is_list(answers) and length(answers) == expected do
        answers
      else
        raise Warden.PolicyError, """
        #{inspect(info.policy)}.allowed_many/4 must return one answer per struct for \
        #{inspect(action)} (#{expected} structs), got #{Info.shape(answers)}\
        """
      end
    end

    defp tenant_groups(sorted) do
      sorted
      |> Enum.flat_map(fn
        {:row, tenant, key} -> [{tenant, key}]
        _other -> []
      end)
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    end

    defp id_values(sorted), do: for({:id, key} <- sorted, do: key)

    defp tenant_queries(info, action, side, by_tenant, state) do
      Enum.reduce(by_tenant, {[], side, state}, fn {tenant, keys}, {queries, side, state} ->
        {verdict, side, state} = Scope.verdict(info, action, side, tenant, state)
        condition = Scope.tenant_condition(info, tenant)
        query = keys_query(info, keys, Scope.both(condition, verdict))
        {[query | queries], side, state}
      end)
    end

    defp id_query(_info, _action, side, [], state), do: {nil, side, state}

    defp id_query(info, action, side, keys, state) do
      {verdict, side, state} = Scope.scope(info, action, side, :all, state)
      {keys_query(info, keys, verdict), side, state}
    end

    defp keys_query(_info, _keys, false), do: nil

    defp keys_query(info, keys, verdict) do
      key = info.primary_key
      keys = Enum.uniq(keys)

      query =
        from(row in info.schema,
          as: ^info.as,
          where: field(row, ^key) in ^keys,
          select: field(row, ^key)
        )

      Scope.restrict(query, verdict)
    end

    # Every query of one decision runs here, one round trip each: the allowed keys of the
    # loaded structs (one query per tenant) and of the `{schema, id}` values.
    defp run(info, tenant_queries, id_query) do
      tenant_queries = Enum.reject(tenant_queries, &is_nil/1)
      allowed_rows = keys(info, tenant_queries)
      allowed_ids = keys(info, List.wrap(id_query))
      {allowed_rows, allowed_ids}
    end

    defp keys(_info, []), do: MapSet.new()

    defp keys(info, queries) do
      repo = Info.repo!(info)
      Enum.reduce(queries, MapSet.new(), &MapSet.union(&2, MapSet.new(repo.all(&1))))
    end

    defp answer(sorted, custom, allowed_rows, allowed_ids) do
      {answers, _custom} =
        Enum.map_reduce(sorted, custom, fn
          {:done, answer}, custom -> {answer, custom}
          {:custom, _struct}, [answer | custom] -> {answer, custom}
          {:row, _tenant, key}, custom -> {MapSet.member?(allowed_rows, key), custom}
          {:id, key}, custom -> {MapSet.member?(allowed_ids, key), custom}
        end)

      answers
    end
  end
end
