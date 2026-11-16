# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Reuse do
    @moduledoc false
    # Decision reuse (`decision_reuse: true`): an object rule decided for an object is
    # not decided again for the same inputs later in the same document execution.
    #
    # Which rules qualify (`scope/2`, decided when the schema compiles), by what the
    # widest leaf reads:
    #
    #   * `:actor` - the actor only (`public()`, `deny()`, `authenticated()`, roles,
    #     permissions, kinds, credential rules), never the context. The tenant binding
    #     screen reads the value's tenant, so values share one decision only for an
    #     unbound actor.
    #   * `:object` - also checks that declare `per_object: true` (but not `single:
    #     true`, whose single and list answers come from different callbacks).
    #     `Warden.Evaluator.object_scoped/2` hands such a check in an object rule no
    #     field, arguments, parent type, argument path or resolution, and the context
    #     without `:loader` (where Absinthe's Dataloader plugin keeps its cache and
    #     replaces it on every resolution pass), so the check reads the actor, the value,
    #     its type, its options and the rest of the context, and nothing else.
    #   * `:context` - also `tenant_role/1,2` without `{:arg, path}` and `can/2` without
    #     `arg:`: the tenant-role callback and the policy get the whole context.
    #   * `:field` - anything else. Never reused: decided per field, as before.
    #
    # A decision is reused only for the same operation (the operation blueprint), the same
    # actor (without its cache) and the same context as far as the rule reads it
    # (`comparable/2`: nothing for `:actor`, the context without `:loader` for `:object`,
    # all of it for `:context`), each compared with `===`.
    #
    # The memo lives in `resolution.acc`, so it ends with the execution. Inside a mutation
    # there is no memo: its root fields run one after another and change state, so a
    # decision made under one root field may not hold under the next.
    #
    # An entry is keyed by type and the value's primary key, but a hit also needs the
    # same rule, the same context and a value equal (`===`) to the one decided: two loads
    # of one row with different fields never share a decision. The primary key only finds
    # the entry. Denials are stored like passes, except a denial that a check timeout
    # caused (reason `:unavailable`), which is asked again.

    alias Absinthe.Blueprint.Document.Operation
    alias Absinthe.Resolution
    alias Warden.{Actor, Evaluator}

    @acc_key Warden
    @unavailable :unavailable

    @actor_leaves [:public, :covered, :deny, :authenticated, :session]
    @actor_tags [:role, :any_role, :permission, :all_permissions, :any_permission, :kind]

    @type scope :: :actor | :object | :context | :field

    # What a rule reads, the widest of its leaves.
    @spec scope(Warden.Rule.t() | nil, map) :: scope
    def scope({tag, rules}, catalog) when tag in [:all, :any] and is_list(rules) do
      rules
      |> Enum.map(&scope(&1, catalog))
      |> Enum.max_by(&rank/1, fn -> :actor end)
    end

    def scope(leaf, _catalog) when leaf in @actor_leaves, do: :actor
    def scope({tag, _value}, _catalog) when tag in @actor_tags, do: :actor
    def scope({:credential_scope, _scope}, _catalog), do: :actor

    def scope({:tenant_role, _role, opts}, _catalog) when is_list(opts) do
      if match?({:arg, _path}, Keyword.get(opts, :tenant)), do: :field, else: :context
    end

    def scope({:can, _policy, _action, opts}, _catalog) when is_list(opts) do
      if Keyword.has_key?(opts, :arg), do: :field, else: :context
    end

    def scope({:check, name, _opts}, catalog) do
      case Evaluator.check_spec(catalog, name) do
        %{per_object: true, single: false} -> :object
        _spec -> :field
      end
    end

    def scope(_rule, _catalog), do: :field

    defp rank(:actor), do: 0
    defp rank(:object), do: 1
    defp rank(:context), do: 2
    defp rank(:field), do: 3

    @spec reusable?(scope) :: boolean
    def reusable?(scope), do: scope in [:actor, :object, :context]

    # The part of the context a rule of `scope` reads.
    @spec comparable(term, scope) :: term
    def comparable(_context, :actor), do: nil
    def comparable(context, :object) when is_map(context), do: Map.delete(context, :loader)
    def comparable(context, _scope), do: context

    # The memo of this execution for `actor`, or nil when decisions may not be reused
    # here: inside a mutation, or when the field is not part of an operation.
    @spec memo(Resolution.t(), Actor.t()) :: map | nil
    def memo(%Resolution{acc: acc} = res, %Actor{} = actor) do
      case operation(res) do
        %Operation{type: type} = operation when type in [:query, :subscription] ->
          identity = uncached(actor)

          case acc do
            %{@acc_key => %{memo: %{operation: stored, actor: owner} = memo}}
            when stored === operation and owner === identity ->
              memo

            _other ->
              %{operation: operation, actor: identity, entries: %{}}
          end

        _mutation_or_unknown ->
          nil
      end
    end

    # The root of a field's path is its operation. A resolution has no other link to it,
    # and the path is as deep as the field, so this walks a few elements once per list
    # decision.
    # credo:disable-for-next-line ExSlop.Check.Refactor.ListLast
    defp operation(%Resolution{path: [_ | _] = path}), do: List.last(path)
    defp operation(_res), do: nil

    @spec put_memo(Resolution.t(), map | nil) :: Resolution.t()
    def put_memo(res, nil), do: res

    def put_memo(%Resolution{acc: acc} = res, memo) do
      state = Map.get(acc, @acc_key, %{})
      %{res | acc: Map.put(acc, @acc_key, Map.put(state, :memo, memo))}
    end

    # The actor without its cache: what an actor is, not what it has read so far.
    @spec uncached(Actor.t()) :: Actor.t()
    def uncached(%Actor{delegator: nil} = actor), do: %{actor | cache: %{}}

    def uncached(%Actor{delegator: %Actor{} = delegator} = actor),
      do: %{actor | cache: %{}, delegator: uncached(delegator)}

    # True when no tenant binding screen reads the value: neither the actor nor its
    # delegator is bound to a tenant.
    @spec unbound?(Actor.t()) :: boolean
    def unbound?(%Actor{delegator: nil} = actor), do: Actor.bound_tenant(actor) == nil

    def unbound?(%Actor{delegator: delegator} = actor),
      do: Actor.bound_tenant(actor) == nil and unbound?(delegator)

    # The key that finds a value's entry: the struct module and its primary key (Ecto
    # schemas), or the struct module (or `:map`) and a non-nil `:id`. `:none` for any
    # other value, which is never stored.
    @spec identity(term) :: term
    def identity(%module{} = value) do
      if function_exported?(module, :__schema__, 1),
        do: schema_identity(module, value),
        else: id_identity(module, value)
    end

    def identity(%{id: id}) when id != nil, do: {:map, id}
    def identity(_value), do: :none

    defp schema_identity(module, value) do
      keys = Enum.map(module.__schema__(:primary_key), &Map.get(value, &1))

      if keys == [] or nil in keys,
        do: :none,
        else: {module, keys}
    end

    defp id_identity(module, %{id: id}) when id != nil, do: {module, id}
    defp id_identity(_module, _value), do: :none

    # The decision stored for `rule` over `value` of `type` under the context `compared`
    # (`comparable/2` of the field's context).
    @spec lookup(map, atom, term, term, term) :: {:ok, term} | :miss
    def lookup(memo, type, rule, value, compared) do
      case Map.fetch(memo.entries, {type, identity(value)}) do
        {:ok, {stored_rule, stored_value, stored_context, result}}
        when stored_rule === rule and stored_value === value and stored_context === compared ->
          {:ok, result}

        _missing ->
          :miss
      end
    end

    @spec store(map, atom, term, term, term, term) :: map
    def store(memo, type, rule, value, compared, result) do
      case {identity(value), lasting?(result)} do
        {:none, _lasting} ->
          memo

        {_identity, false} ->
          memo

        {identity, true} ->
          entry = {rule, value, compared, result}
          %{memo | entries: Map.put(memo.entries, {type, identity}, entry)}
      end
    end

    # The decision of an `:actor` rule of `type`, for every value (unbound actor only).
    # Such a rule reads no context.
    @spec lookup_actor(map, atom, term) :: {:ok, term} | :miss
    def lookup_actor(memo, type, rule) do
      case Map.fetch(memo.entries, {type, :actor}) do
        {:ok, {stored_rule, result}} when stored_rule === rule -> {:ok, result}
        _missing -> :miss
      end
    end

    @spec store_actor(map, atom, term, term) :: map
    def store_actor(memo, type, rule, result) do
      if lasting?(result),
        do: %{memo | entries: Map.put(memo.entries, {type, :actor}, {rule, result})},
        else: memo
    end

    # A denial a check timeout caused may pass when asked again; it is never stored.
    defp lasting?(:ok), do: true

    defp lasting?({:deny, failure}) do
      not (unavailable?(Map.get(failure, :reason)) or
             Enum.any?(Map.get(failure, :trace, []), &match?({_rule, {:deny, @unavailable}}, &1)))
    end

    defp unavailable?(@unavailable), do: true
    defp unavailable?(reasons) when is_list(reasons), do: Enum.any?(reasons, &unavailable?/1)
    defp unavailable?(_reason), do: false
  end
end
