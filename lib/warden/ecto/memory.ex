# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Memory do
    @moduledoc false
    # Decides a loaded struct from the policy's clauses without a query, where that is
    # exact: `true`, `false` or `:unknown` (then a query decides). Exact means the answer
    # equals the scope's for a struct that matches its database row:
    #
    #   * `rule:` is about the actor only;
    #   * `where:`, `actor_in:` and `within:` compare fields whose Elixir equality is the
    #     database's (ids, integers, booleans, strings, enums, `nil`);
    #   * `through:` uses the loaded parent when its key matches the foreign key;
    #   * `through_any:` is `true` when a loaded child is allowed, else unknown (a preload
    #     may have been filtered);
    #   * `through_type:` is `false` for a type not in the map, else unknown;
    #   * `none:`, `member_of:`, `grant:`, `when:` and a hand-written `scope/4` are unknown.
    #
    # Three-valued logic: AND is `false` if any part is, `true` if all are; OR is `true` if
    # any is, `false` if all are; otherwise `:unknown`.

    alias Ecto.Association.NotLoaded
    alias Warden.Actor
    alias Warden.Ecto.{Info, Scope}
    alias Warden.Ecto.Policy.Compiler

    @type answer :: boolean | :unknown

    # Decides `struct` for one side of an actor (never delegated). A hand-written
    # `allowed?/4` answers when the policy has one.
    @spec decide(map, atom, Actor.t(), struct, Scope.t()) :: {answer, Actor.t(), Scope.t()}
    def decide(info, action, actor, struct, state) do
      tenant = tenant(info, struct)

      case Scope.gate(info, actor, tenant, state) do
        {nil, state} when info.allowed? ->
          {custom(info, action, actor, struct, state.context), actor, state}

        {nil, state} ->
          planned(info, action, actor, tenant, struct, state)

        {_reason, state} ->
          {false, actor, state}
      end
    end

    @spec tenant(map, struct) :: term
    def tenant(%{tenant: nil}, _struct), do: nil
    def tenant(info, struct), do: Map.get(struct, info.tenant)

    defp custom(info, action, actor, struct, context) do
      case info.policy.allowed?(action, actor, struct, context) do
        true ->
          true

        false ->
          false

        {:deny, _reason} ->
          false

        other ->
          raise Warden.PolicyError,
                "#{inspect(info.policy)}.allowed?/4 returned #{inspect(other)}"
      end
    end

    defp planned(info, action, actor, tenant, struct, state) do
      case Map.fetch!(info.actions, action) do
        :scope ->
          {:unknown, actor, state}

        {:clauses, requires, allows} ->
          {required, actor, state} = all(requires, info, actor, tenant, struct, state)

          if required == false do
            {false, actor, state}
          else
            allows = Scope.applicable(allows, actor)
            {allowed, actor, state} = any(allows, info, actor, tenant, struct, state)
            {both(required, allowed), actor, state}
          end
      end
    end

    defp all([], _info, actor, _tenant, _struct, state), do: {true, actor, state}

    defp all([clause | rest], info, actor, tenant, struct, state) do
      {answer, actor, state} = clause(info, clause, actor, tenant, struct, state)

      if answer == false do
        {false, actor, state}
      else
        {others, actor, state} = all(rest, info, actor, tenant, struct, state)
        {both(answer, others), actor, state}
      end
    end

    defp any([], _info, actor, _tenant, _struct, state), do: {false, actor, state}

    defp any([clause | rest], info, actor, tenant, struct, state) do
      {answer, actor, state} = clause(info, clause, actor, tenant, struct, state)

      if answer == true do
        {true, actor, state}
      else
        {others, actor, state} = any(rest, info, actor, tenant, struct, state)
        {either(answer, others), actor, state}
      end
    end

    defp clause(info, clause, actor, tenant, struct, state) do
      clause.parts
      |> Scope.ordered()
      |> Enum.reduce_while({true, actor, state}, fn part, {acc, actor, state} ->
        {answer, actor, state} = part(info, clause, part, actor, tenant, struct, state)
        combined = both(acc, answer)

        if combined == false,
          do: {:halt, {false, actor, state}},
          else: {:cont, {combined, actor, state}}
      end)
    end

    defp part(info, clause, {:rule, rule}, actor, tenant, _struct, state),
      do: Scope.rule_verdict(info, clause, rule, actor, tenant, state)

    defp part(info, _clause, {:where, conditions}, actor, _tenant, struct, state) do
      answer =
        Enum.reduce(conditions, true, fn {field, value}, acc ->
          both(acc, field_equals(info, struct, field, value))
        end)

      {answer, actor, state}
    end

    defp part(
           info,
           clause,
           {:through, assoc, through_action, if_nil},
           actor,
           tenant,
           struct,
           state
         ) do
      association = info.schema.__schema__(:association, assoc)
      foreign_key = Map.get(struct, association.owner_key)
      loaded = Map.get(struct, association.field)
      action = through_action || clause.action

      cond do
        foreign_key == nil -> if_nil(info, if_nil, actor, tenant, state)
        match?(%NotLoaded{}, loaded) or loaded == nil -> {:unknown, actor, state}
        Map.get(loaded, association.related_key) != foreign_key -> {:unknown, actor, state}
        true -> parent(info, association.related, action, actor, tenant, loaded, state)
      end
    end

    defp part(info, clause, {:through_any, assoc, through_action}, actor, tenant, struct, state) do
      association = info.schema.__schema__(:association, assoc)
      action = through_action || clause.action

      case Map.get(struct, association.field) do
        children when is_list(children) ->
          any_child(info, association.related, action, actor, tenant, children, state)

        _not_loaded ->
          {:unknown, actor, state}
      end
    end

    defp part(info, _clause, {:actor_in, fields}, actor, _tenant, struct, state) do
      answer =
        case Scope.subject_id(info, actor) do
          nil ->
            false

          id ->
            Enum.reduce(fields, false, fn field, acc ->
              either(acc, field_equals(info, struct, field, id))
            end)
        end

      {answer, actor, state}
    end

    defp part(
           info,
           _clause,
           {:through_type, {type_field, _id_field, targets}},
           actor,
           _tenant,
           struct,
           state
         ) do
      answer = if Map.has_key?(targets, Map.get(struct, type_field)), do: :unknown, else: false
      answer = if exact?(info, type_field), do: answer, else: :unknown
      {answer, actor, state}
    end

    defp part(info, _clause, {:within, bounds_key, field}, actor, _tenant, struct, state) do
      answer =
        case Scope.bounds!(actor, bounds_key, info) do
          nil -> false
          ids -> if exact?(info, field), do: Map.get(struct, field) in ids, else: :unknown
        end

      {answer, actor, state}
    end

    defp part(_info, _clause, _part, actor, _tenant, _struct, state), do: {:unknown, actor, state}

    defp field_equals(info, struct, field, value) do
      cond do
        value == nil -> Map.get(struct, field) == nil
        exact?(info, field) -> Map.get(struct, field) == value
        true -> :unknown
      end
    end

    defp exact?(info, field), do: Compiler.exact_type?(info.schema.__schema__(:type, field))

    defp if_nil(_info, :deny, actor, _tenant, state), do: {false, actor, state}

    defp if_nil(info, :tenant, actor, tenant, state) do
      {roles, actor} = Actor.tenant_roles(actor, tenant, state.context, info.authorizer)
      {MapSet.size(roles) > 0, actor, state}
    end

    # A loaded parent in another tenant is not the parent the scope would find.
    defp parent(info, related, action, actor, tenant, loaded, state) do
      parent = Info.policy_for!(info.authorizer, related)

      if tenant(parent, loaded) == tenant,
        do: decide(parent, action, actor, loaded, state),
        else: {false, actor, state}
    end

    defp any_child(info, related, action, actor, tenant, children, state) do
      child = Info.policy_for!(info.authorizer, related)

      Enum.reduce_while(children, {:unknown, actor, state}, fn loaded, {_acc, actor, state} ->
        {answer, actor, state} =
          if tenant(child, loaded) == tenant,
            do: decide(child, action, actor, loaded, state),
            else: {false, actor, state}

        if answer == true,
          do: {:halt, {true, actor, state}},
          else: {:cont, {:unknown, actor, state}}
      end)
    end

    @spec both(answer, answer) :: answer
    def both(false, _right), do: false
    def both(_left, false), do: false
    def both(true, right), do: right
    def both(left, true), do: left
    def both(:unknown, :unknown), do: :unknown

    @spec either(answer, answer) :: answer
    def either(true, _right), do: true
    def either(_left, true), do: true
    def either(false, right), do: right
    def either(left, false), do: left
    def either(:unknown, :unknown), do: :unknown
  end
end
