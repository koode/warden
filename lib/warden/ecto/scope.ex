# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Scope do
    @moduledoc false
    # Builds the query scope of a policy action: an Ecto dynamic over the policy's `as:`
    # binding, `true` or `false`.
    #
    # `verdict/5` decides one side of an actor (never a delegated actor) in one tenant:
    # the gates (system kinds, the credential's tenant binding, `NULL` tenants), then the
    # hand-written `scope/4` or the clauses. Results are memoized per policy, action,
    # tenant and actor in the state, so every callback runs at most once per call, and a
    # `through` parent's scope is built once and reused. `scope/5` adds the tenant
    # conditions and, for a delegated actor, ANDs both sides. `preload_ids/5` puts the
    # parent ids of `resolve: :ids` in the actor's cache, so later calls read them there.

    import Ecto.Query, only: [dynamic: 1, dynamic: 2, from: 2, where: 2, where: 3]

    alias Ecto.Association.{BelongsTo, Has, ManyToMany}
    alias Warden.{Actor, Check, Evaluator}
    alias Warden.Ecto.Info

    defstruct context: %{}, memo: %{}, stack: [], prefix: nil

    # `prefix` is the query prefix the scope runs in, for the parent ids that
    # `through: {assoc, action, resolve: :ids}` reads while the scope is built.
    @type t :: %__MODULE__{context: map, memo: map, stack: [{module, atom}], prefix: term}
    @type verdict :: Ecto.Query.dynamic_expr() | boolean

    @spec new(map) :: t
    def new(context, prefix \\ nil), do: %__MODULE__{context: context, prefix: prefix}

    # The scope over the rows of one tenant (`{:tenant, tenant}`) or of every tenant the
    # actor may act in (`:all`), tenant conditions included.
    @spec scope(map, atom, Actor.t(), :all | {:tenant, term}, t) :: {verdict, Actor.t(), t}
    def scope(info, action, %Actor{} = actor, which, state) do
      Info.ensure_action!(info, action)

      case tenants(info, actor, which, state) do
        {:untenanted, state} -> both_sides(info, action, actor, nil, state)
        {tenants, state} -> tenants_scope(info, action, actor, tenants, state)
      end
    end

    defp tenants(%{tenant: nil}, _actor, {:tenant, nil}, state), do: {:untenanted, state}
    defp tenants(%{tenant: nil}, _actor, :all, state), do: {:untenanted, state}

    defp tenants(%{tenant: nil, policy: policy}, _actor, {:tenant, _tenant}, _state) do
      raise ArgumentError, "#{inspect(policy)} has no `:tenant`, so it takes no `tenant:` option"
    end

    defp tenants(_info, _actor, {:tenant, tenant}, state), do: {[tenant], state}

    defp tenants(info, actor, :all, state) do
      {own, state} = actor_tenants(%{actor | delegator: nil}, state)

      {listed, state} =
        case actor.delegator do
          nil ->
            {own, state}

          delegator ->
            {theirs, state} = actor_tenants(delegator, state)
            {Enum.filter(own, &(&1 in theirs)), state}
        end

      listed = Enum.uniq(listed)
      tenants = if info.null_tenant, do: listed ++ [nil], else: listed
      {tenants, state}
    end

    defp tenants_scope(info, action, actor, tenants, state) do
      {parts, {actor, state}} =
        Enum.map_reduce(tenants, {actor, state}, fn tenant, {actor, state} ->
          {verdict, actor, state} = both_sides(info, action, actor, tenant, state)
          {{tenant, verdict}, {actor, state}}
        end)

      everywhere = for {tenant, true} <- parts, tenant != nil, do: tenant

      in_tenants =
        if everywhere == [],
          do: false,
          else: dynamic([{^info.as, row}], field(row, ^info.tenant) in ^everywhere)

      verdict =
        Enum.reduce(parts, in_tenants, fn
          {tenant, true}, acc when tenant != nil -> acc
          {_tenant, false}, acc -> any(acc, false)
          {tenant, verdict}, acc -> any(acc, both(tenant_condition(info, tenant), verdict))
        end)

      {verdict, actor, state}
    end

    # The AND of the actor's verdict and its delegator's, in one tenant.
    defp both_sides(info, action, %Actor{delegator: nil} = actor, tenant, state),
      do: verdict(info, action, actor, tenant, state)

    defp both_sides(info, action, %Actor{delegator: delegator} = actor, tenant, state) do
      {own, side, state} = verdict(info, action, %{actor | delegator: nil}, tenant, state)

      if own == false do
        {false, %{side | delegator: delegator}, state}
      else
        {theirs, delegator, state} = verdict(info, action, delegator, tenant, state)
        {both(own, theirs), %{side | delegator: delegator}, state}
      end
    end

    # The row condition for `tenant`: `field = tenant`, or `IS NULL` for `nil`.
    @spec tenant_condition(map, term) :: Ecto.Query.dynamic_expr() | true
    def tenant_condition(%{tenant: nil}, _tenant), do: true

    def tenant_condition(info, nil),
      do: dynamic([{^info.as, row}], is_nil(field(row, ^info.tenant)))

    def tenant_condition(info, tenant),
      do: dynamic([{^info.as, row}], field(row, ^info.tenant) == ^tenant)

    # One side of an actor, one tenant: the gates, then the policy.
    @spec verdict(map, atom, Actor.t(), term, t) :: {verdict, Actor.t(), t}
    def verdict(info, action, %Actor{} = actor, tenant, state) do
      # A verdict with `resolve: :ids` holds the parent ids of one prefix.
      key = {info.policy, action, tenant, identity(actor), state.prefix}

      case Map.fetch(state.memo, key) do
        {:ok, verdict} ->
          {verdict, actor, state}

        :error ->
          {verdict, actor, state} = decide(info, action, actor, tenant, state)
          {verdict, actor, %{state | memo: Map.put(state.memo, key, verdict)}}
      end
    end

    # The actor without its cache (tenant roles, tenants and preloaded parent ids), which
    # changes while the actor is used, and without its instance reference: two actors
    # that differ only in instance decide alike, so they share memoized verdicts and
    # cached ids. Row marks check the instance themselves (`Warden.Ecto.Mark`).
    @spec identity(Actor.t()) :: Actor.t()
    def identity(%Actor{} = actor), do: %{actor | cache: %{}, instance: nil}

    defp decide(info, action, actor, tenant, state) do
      case gate(info, actor, tenant, state) do
        {nil, state} -> planned(info, action, actor, tenant, state)
        {_reason, state} -> {false, actor, state}
      end
    end

    defp planned(info, action, actor, tenant, state) do
      step = {info.policy, action}

      if step in state.stack do
        raise Warden.PolicyError,
              "a through cycle reaches #{inspect(info.policy)} #{inspect(action)} again"
      end

      outer = state.stack

      {verdict, actor, state} =
        plan(info, action, actor, tenant, %{state | stack: [step | outer]})

      {verdict, actor, %{state | stack: outer}}
    end

    # Why a row of `tenant` is denied before the policy is asked, or `nil`:
    #
    #   * `:system_kind` - a system actor of a kind the policy does not name;
    #   * `:null_tenant` - a `NULL` tenant the policy does not opt into;
    #   * `:tenant_binding` - a tenant other than the one the actor's credential is bound
    #     to (an untenanted row has no tenant, so a bound actor gets nothing there);
    #   * `:not_a_tenant` - a tenant that is not one of the actor's
    #     (`Warden.Actor.tenants/2`), so a single check never admits a row that the scope
    #     over every tenant of the actor leaves out.
    @spec gate(map, Actor.t(), term, t) :: {atom | nil, t}
    def gate(info, actor, tenant, state) do
      case static_gate(info, actor, tenant) do
        nil when info.tenant == nil or tenant == nil -> {nil, state}
        nil -> member_gate(actor, tenant, state)
        reason -> {reason, state}
      end
    end

    defp static_gate(info, actor, tenant) do
      cond do
        actor.system? and Actor.kind(actor) not in info.system_kinds -> :system_kind
        info.tenant != nil and tenant == nil and not info.null_tenant -> :null_tenant
        not Actor.tenant_allowed?(actor, tenant) -> :tenant_binding
        true -> nil
      end
    end

    defp member_gate(actor, tenant, state) do
      {tenants, state} = actor_tenants(actor, state)
      if tenant in tenants, do: {nil, state}, else: {:not_a_tenant, state}
    end

    # `Warden.Actor.tenants/2` of one side, once per call.
    defp actor_tenants(actor, state) do
      key = {:tenants, identity(actor)}

      case Map.fetch(state.memo, key) do
        {:ok, tenants} ->
          {tenants, state}

        :error ->
          tenants = Actor.tenants(actor, state.context)
          {tenants, %{state | memo: Map.put(state.memo, key, tenants)}}
      end
    end

    defp plan(info, action, actor, tenant, state) do
      case Map.fetch!(info.actions, action) do
        :scope ->
          result = info.policy.scope(action, actor, tenant, state.context)

          {checked!(result, "#{inspect(info.policy)}.scope(#{inspect(action)}, ...)"), actor,
           state}

        {:clauses, requires, allows} ->
          clauses(info, requires, allows, actor, tenant, state)
      end
    end

    # Requires first: one that is `false` saves asking the allows.
    defp clauses(info, requires, allows, actor, tenant, state) do
      {required, actor, state} = all_clauses(info, requires, actor, tenant, state)

      if required == false do
        {false, actor, state}
      else
        allows = applicable(allows, actor)
        {allowed, actor, state} = any_clause(info, allows, actor, tenant, state)
        {both(required, allowed), actor, state}
      end
    end

    # A system actor passes only allow clauses whose `rule:` names its kind.
    @spec applicable([map], Actor.t()) :: [map]
    # A clause with `through:` or `through_any:` and `system: :inherit` applies too: the
    # related policy then decides the system actor, and admits only the kinds it admits.
    def applicable(allows, %Actor{system?: true} = actor) do
      kind = Actor.kind(actor)
      Enum.filter(allows, &(names_kind?(&1, kind) or inherits_system?(&1)))
    end

    def applicable(allows, %Actor{}), do: allows

    defp names_kind?(clause, kind) do
      Enum.any?(clause.parts, fn
        {:rule, rule} -> rule_names_kind?(rule, kind)
        _part -> false
      end)
    end

    defp inherits_system?(clause) do
      Enum.any?(clause.parts, fn
        {:through, _assoc, _action, _if_nil, %{system: :inherit}} -> true
        {:through_any, _assoc, _action, %{system: :inherit}} -> true
        _part -> false
      end)
    end

    defp rule_names_kind?({:kind, kinds}, kind), do: kind in kinds

    defp rule_names_kind?({tag, rules}, kind) when tag in [:all, :any] and is_list(rules),
      do: Enum.any?(rules, &rule_names_kind?(&1, kind))

    defp rule_names_kind?(_rule, _kind), do: false

    defp all_clauses(_info, [], actor, _tenant, state), do: {true, actor, state}

    defp all_clauses(info, [clause | rest], actor, tenant, state) do
      {verdict, actor, state} = clause(info, clause, actor, tenant, state)

      if verdict == false do
        {false, actor, state}
      else
        {others, actor, state} = all_clauses(info, rest, actor, tenant, state)
        {both(verdict, others), actor, state}
      end
    end

    defp any_clause(_info, [], actor, _tenant, state), do: {false, actor, state}

    defp any_clause(info, [clause | rest], actor, tenant, state) do
      {verdict, actor, state} = clause(info, clause, actor, tenant, state)

      if verdict == true do
        {true, actor, state}
      else
        {others, actor, state} = any_clause(info, rest, actor, tenant, state)
        {any(verdict, others), actor, state}
      end
    end

    # One clause: its parts ANDed, the actor-only `rule:` first.
    @spec clause(map, map, Actor.t(), term, t) :: {verdict, Actor.t(), t}
    def clause(info, clause, actor, tenant, state) do
      clause.parts
      |> ordered()
      |> all_parts(info, clause, actor, tenant, state)
    end

    @spec ordered(list) :: list
    def ordered(parts), do: Enum.sort_by(parts, &(elem(&1, 0) != :rule))

    defp all_parts([], _info, _clause, actor, _tenant, state), do: {true, actor, state}

    defp all_parts([part | rest], info, clause, actor, tenant, state) do
      {verdict, actor, state} = part(info, clause, part, actor, tenant, state)

      if verdict == false do
        {false, actor, state}
      else
        {others, actor, state} = all_parts(rest, info, clause, actor, tenant, state)
        {both(verdict, others), actor, state}
      end
    end

    # One part of a clause.
    @spec part(map, map, tuple, Actor.t(), term, t) :: {verdict, Actor.t(), t}
    def part(info, clause, {:rule, rule}, actor, tenant, state) do
      rule_verdict(info, clause, rule, actor, tenant, state)
    end

    def part(info, _clause, {:where, conditions}, actor, _tenant, state) do
      verdict = Enum.reduce(conditions, true, &both(&2, equals(info, &1)))
      {verdict, actor, state}
    end

    def part(info, clause, {:through, assoc, through_action, if_nil, opts}, actor, tenant, state) do
      association = info.schema.__schema__(:association, assoc)
      parent = Info.policy_for!(info.authorizer, association.related)
      action = through_action || clause.action
      {parent_verdict, actor, state} = verdict(parent, action, actor, tenant, state)

      {parent_condition, state} =
        case opts.resolve do
          :exists ->
            {parent_exists(info, parent, association, parent_verdict, tenant), state}

          :ids ->
            parent_in(info, parent, action, association, parent_verdict, actor, tenant, state)
        end

      {nil_branch, actor} = nil_branch(info, association, if_nil, actor, tenant, state.context)
      {any(parent_condition, nil_branch), actor, state}
    end

    def part(info, clause, {:through_any, assoc, through_action, _opts}, actor, tenant, state) do
      association = info.schema.__schema__(:association, assoc)
      child = Info.policy_for!(info.authorizer, association.related)
      action = through_action || clause.action
      {child_verdict, actor, state} = verdict(child, action, actor, tenant, state)

      exists =
        if child_verdict == false,
          do: false,
          else: children_exist(info, association, child, child_verdict, tenant)

      {exists, actor, state}
    end

    def part(info, _clause, {:none, assoc}, actor, _tenant, state) do
      association = info.schema.__schema__(:association, assoc)
      exists = children_exist(info, association, nil, true, nil)
      {dynamic(not (^exists)), actor, state}
    end

    def part(info, _clause, {:actor_in, fields}, actor, _tenant, state) do
      verdict =
        case subject_id(info, actor) do
          nil ->
            false

          id ->
            for field <- fields, {:ok, cast} <- [cast(info, field, id)], reduce: false do
              acc -> any(acc, dynamic([{^info.as, row}], field(row, ^field) == ^cast))
            end
        end

      {verdict, actor, state}
    end

    def part(info, _clause, {:member_of, link, row_key, actor_key}, actor, _tenant, state) do
      verdict =
        case subject_id(info, actor) do
          nil -> false
          id -> dynamic(exists(link_query(info, link, row_key, actor_key, id)))
        end

      {verdict, actor, state}
    end

    def part(info, _clause, {:grant, link, row_key, grantee_key, expires}, actor, _tenant, state) do
      verdict =
        case subject_id(info, actor) do
          nil ->
            false

          id ->
            query = info |> link_query(link, row_key, grantee_key, id) |> unexpired(link, expires)
            dynamic(exists(query))
        end

      {verdict, actor, state}
    end

    def part(info, clause, {:through_type, {type_field, id_field, targets}}, actor, tenant, state) do
      targets
      |> Enum.sort()
      |> Enum.reduce({false, actor, state}, fn {type, {policy, through_action}}, acc ->
        {verdict, actor, state} = acc
        parent = Info.fetch!(policy)
        action = through_action || clause.action
        {parent_verdict, actor, state} = verdict(parent, action, actor, tenant, state)
        exists = typed_parent_exists(info, parent, id_field, parent_verdict, tenant)
        of_type = dynamic([{^info.as, row}], field(row, ^type_field) == ^type)
        {any(verdict, both(of_type, exists)), actor, state}
      end)
    end

    # A missing bounds key denies, unless the clause opts in with `if_missing: :allow`
    # (an optional limit, such as a credential's team limit).
    def part(info, _clause, {:within, bounds_key, field, if_missing}, actor, _tenant, state) do
      verdict =
        case bounds!(actor, bounds_key, info) do
          nil -> if_missing == :allow
          bounds -> bounds_in(info, field, bounds)
        end

      {verdict, actor, state}
    end

    def part(info, _clause, {:when, {:function, name}}, actor, tenant, state) do
      result = apply(info.policy, name, [actor, tenant, state.context])
      {checked!(result, "the `when:` function of #{inspect(info.policy)}"), actor, state}
    end

    # A `rule:` part, evaluated once per policy, clause, tenant and actor.
    @spec rule_verdict(map, map, term, Actor.t(), term, t) :: {boolean, Actor.t(), t}
    def rule_verdict(info, clause, rule, actor, tenant, state) do
      key = {:rule, info.policy, clause.action, clause.index, tenant, identity(actor)}

      case Map.fetch(state.memo, key) do
        {:ok, passed} ->
          {passed, actor, state}

        :error ->
          check = %Check{
            actor: actor,
            value: nil,
            args: %{tenant: tenant},
            context: state.context
          }

          {result, actor, _tenant} = Evaluator.one(rule, check, info.authorizer)
          passed = result == :ok
          {passed, actor, %{state | memo: Map.put(state.memo, key, passed)}}
      end
    end

    defp equals(info, {field, nil}),
      do: dynamic([{^info.as, row}], is_nil(field(row, ^field)))

    defp equals(info, {field, value}),
      do: dynamic([{^info.as, row}], field(row, ^field) == ^value)

    # EXISTS a parent row, in the same tenant, that the parent's verdict admits.
    defp parent_exists(_info, _parent, _association, false, _tenant), do: false

    defp parent_exists(info, parent, %BelongsTo{} = association, verdict, tenant) do
      %{owner_key: owner_key, related_key: related_key} = association

      query =
        from(parent_row in parent.schema,
          as: ^parent.as,
          where: field(parent_row, ^related_key) == field(parent_as(^info.as), ^owner_key),
          select: 1
        )

      query = query |> restrict(tenant_condition(parent, tenant)) |> restrict(verdict)
      dynamic(exists(query))
    end

    # `resolve: :ids`: the parent's scope runs once per actor, tenant and call, and the
    # row's foreign key is compared with the ids it returns (`fk = ANY($ids)`). The ids are
    # the parent rows of the same tenant, so the tenant condition holds as with EXISTS.
    defp parent_in(_info, _parent, _action, _association, false, _actor, _tenant, state),
      do: {false, state}

    defp parent_in(info, parent, action, association, verdict, actor, tenant, state) do
      related_key = association.related_key
      key = ids_key(parent, action, related_key, tenant, actor, state)

      {ids, state} =
        case fetch_ids(key, actor, state) do
          {:ok, ids} -> {ids, state}
          :error -> read_ids(parent, related_key, verdict, tenant, key, state)
        end

      condition =
        if ids == [],
          do: false,
          else: dynamic([{^info.as, row}], field(row, ^association.owner_key) in ^ids)

      {condition, state}
    end

    # The key of one side's parent ids, in the call's memo and in the actor's cache: the
    # parent policy, the action, the column read, the tenant, the side (without its cache)
    # and the query prefix. A side's cache entry is never used for the other side, nor for
    # another tenant, prefix or action.
    defp ids_key(parent, action, related_key, tenant, actor, state),
      do: {:ids, parent.policy, action, related_key, tenant, identity(actor), state.prefix}

    # The ids from the call's memo, else from the side's cache (`preload_ids/5`).
    defp fetch_ids(key, actor, state) do
      with :error <- Map.fetch(state.memo, key), do: Map.fetch(actor.cache, key)
    end

    # Reads the ids that `resolve: :ids` compares a foreign key with (the primary key of
    # `info`'s rows), for each tenant (as `scope/5` lists them) and each side of the
    # actor, and returns the actor with each side's ids in that side's own cache. A
    # delegator whose actor sees no parent row is not asked, as in `scope/5`.
    @spec preload_ids(map, atom, Actor.t(), :all | {:tenant, term}, t) :: Actor.t()
    def preload_ids(info, action, %Actor{} = actor, which, state) do
      Info.ensure_action!(info, action)

      {tenants, state} =
        case tenants(info, actor, which, state) do
          {:untenanted, state} -> {[nil], state}
          listed -> listed
        end

      {actor, _state} =
        Enum.reduce(tenants, {actor, state}, fn tenant, {actor, state} ->
          both_sides_ids(info, action, actor, tenant, state)
        end)

      actor
    end

    defp both_sides_ids(info, action, %Actor{delegator: nil} = actor, tenant, state) do
      {_verdict, actor, state} = side_ids(info, action, actor, tenant, state)
      {actor, state}
    end

    defp both_sides_ids(info, action, %Actor{delegator: delegator} = actor, tenant, state) do
      {own, side, state} = side_ids(info, action, %{actor | delegator: nil}, tenant, state)

      if own == false do
        {%{side | delegator: delegator}, state}
      else
        {_theirs, delegator, state} = side_ids(info, action, delegator, tenant, state)
        {%{side | delegator: delegator}, state}
      end
    end

    # One side's verdict, then its ids in its cache (none to read when it is `false`).
    defp side_ids(info, action, side, tenant, state) do
      {verdict, side, state} = verdict(info, action, side, tenant, state)

      if verdict == false do
        {false, side, state}
      else
        key = ids_key(info, action, info.primary_key, tenant, side, state)

        {ids, state} =
          case fetch_ids(key, side, state) do
            {:ok, ids} -> {ids, state}
            :error -> read_ids(info, info.primary_key, verdict, tenant, key, state)
          end

        cached = %{side | cache: Map.put(side.cache, key, ids)}
        {verdict, cached, state}
      end
    end

    defp read_ids(parent, related_key, verdict, tenant, key, state) do
      query =
        from(parent_row in parent.schema,
          as: ^parent.as,
          select: field(parent_row, ^related_key)
        )

      query = query |> restrict(tenant_condition(parent, tenant)) |> restrict(verdict)
      query = %{query | prefix: state.prefix}
      repo = Info.repo!(parent)
      ids = repo.all(query)
      {ids, %{state | memo: Map.put(state.memo, key, ids)}}
    end

    defp typed_parent_exists(_info, _parent, _id_field, false, _tenant), do: false

    defp typed_parent_exists(info, parent, id_field, verdict, tenant) do
      key = parent.primary_key

      query =
        from(parent_row in parent.schema,
          as: ^parent.as,
          where: field(parent_row, ^key) == field(parent_as(^info.as), ^id_field),
          select: 1
        )

      query = query |> restrict(tenant_condition(parent, tenant)) |> restrict(verdict)
      dynamic(exists(query))
    end

    # EXISTS a row of a has_many or many_to_many association; with a child policy, one in
    # the same tenant that the child's verdict admits.
    defp children_exist(info, %Has{} = association, child, verdict, tenant) do
      %{owner_key: owner_key, related_key: related_key, related: related} = association

      query =
        from(child_row in related,
          as: ^child_as(child),
          where: field(child_row, ^related_key) == field(parent_as(^info.as), ^owner_key),
          select: 1
        )

      restricted = child_restrict(query, child, verdict, tenant)
      dynamic(exists(restricted))
    end

    # `none:` over a many_to_many asks the join table alone: any link row counts, so the
    # far table is never joined.
    defp children_exist(info, %ManyToMany{} = association, nil, _verdict, _tenant) do
      [{join_owner_key, owner_key} | _related] = association.join_keys
      join_through = association.join_through

      query =
        from(link in join_through,
          where: field(link, ^join_owner_key) == field(parent_as(^info.as), ^owner_key),
          select: 1
        )

      dynamic(exists(query))
    end

    defp children_exist(info, %ManyToMany{} = association, child, verdict, tenant) do
      %{join_through: join_through, join_keys: join_keys, related: related} = association
      [{join_owner_key, owner_key}, {join_related_key, related_key}] = join_keys

      query =
        from(child_row in related,
          as: ^child_as(child),
          join: link in ^join_through,
          on: field(link, ^join_related_key) == field(child_row, ^related_key),
          where: field(link, ^join_owner_key) == field(parent_as(^info.as), ^owner_key),
          select: 1
        )

      restricted = child_restrict(query, child, verdict, tenant)
      dynamic(exists(restricted))
    end

    defp child_as(nil), do: :warden_child
    defp child_as(child), do: child.as

    defp child_restrict(query, nil, _verdict, _tenant), do: query

    defp child_restrict(query, child, verdict, tenant),
      do: query |> restrict(tenant_condition(child, tenant)) |> restrict(verdict)

    # With `if_nil: :tenant`, a row whose foreign key is `nil` is visible to members of
    # the tenant (actors with any tenant role there).
    defp nil_branch(_info, _association, :deny, actor, _tenant, _context), do: {false, actor}

    defp nil_branch(info, association, :tenant, actor, tenant, context) do
      {roles, actor} = Actor.tenant_roles(actor, tenant, context, info.authorizer)

      if MapSet.size(roles) == 0,
        do: {false, actor},
        else: {dynamic([{^info.as, row}], is_nil(field(row, ^association.owner_key))), actor}
    end

    defp link_query(info, link, row_key, actor_key, id) do
      from(link_row in link,
        where: field(link_row, ^row_key) == field(parent_as(^info.as), ^info.primary_key),
        where: field(link_row, ^actor_key) == ^id,
        select: 1
      )
    end

    defp unexpired(query, _link, nil), do: query

    defp unexpired(query, link, expires) do
      now = now(link, expires)

      where(
        query,
        [link_row],
        is_nil(field(link_row, ^expires)) or field(link_row, ^expires) > ^now
      )
    end

    # The current time in the type of the `expires_at` field (the compiler requires a
    # schema for `grant:` with `expires_at:`).
    defp now(link, expires) do
      case link.__schema__(:type, expires) do
        :utc_datetime -> DateTime.truncate(DateTime.utc_now(), :second)
        :utc_datetime_usec -> DateTime.utc_now()
        :naive_datetime -> NaiveDateTime.truncate(NaiveDateTime.utc_now(), :second)
        _usec -> NaiveDateTime.utc_now()
      end
    end

    # Adds a verdict to a query as a `where`.
    @spec restrict(Ecto.Query.t(), verdict) :: Ecto.Query.t()
    def restrict(query, true), do: query
    def restrict(query, false), do: where(query, false)
    def restrict(query, %Ecto.Query.DynamicExpr{} = verdict), do: where(query, ^verdict)

    # The actor's subject id: `nil` for anonymous and system actors, and for a subject
    # that is not a map.
    @spec subject_id(map, Actor.t()) :: term
    def subject_id(_info, %Actor{system?: true}), do: nil

    def subject_id(info, %Actor{subject: subject}) when is_map(subject),
      do: Map.get(subject, info.subject_id)

    def subject_id(_info, %Actor{}), do: nil

    # The actor's bounds under `key`: `nil` when missing, else a list.
    @spec bounds!(Actor.t(), term, map) :: list | nil
    def bounds!(%Actor{bounds: bounds}, key, info) do
      case Map.get(bounds, key) do
        nil ->
          nil

        list when is_list(list) ->
          # A NULL column is never inside the bounds.
          Enum.reject(list, &is_nil/1)

        other ->
          raise Warden.PolicyError, """
          #{inspect(info.policy)}: the actor's bounds[#{inspect(key)}] must be a list, got: \
          #{Info.shape(other)}\
          """
      end
    end

    defp bounds_in(info, field, bounds) do
      case cast_all(info, field, bounds) do
        [] -> false
        ids -> dynamic([{^info.as, row}], field(row, ^field) in ^ids)
      end
    end

    # A bound or subject id cast through the field's Ecto type, as the query would cast
    # it, so the in-memory path compares the same values. A value that does not cast
    # matches nothing (the query would raise).
    @spec cast(map, atom, term) :: {:ok, term} | :error
    def cast(info, field, value) do
      case Ecto.Type.cast(info.schema.__schema__(:type, field), value) do
        {:ok, cast} when cast != nil -> {:ok, cast}
        _invalid -> :error
      end
    end

    @spec cast_all(map, atom, list) :: list
    def cast_all(info, field, values),
      do: for(value <- values, {:ok, cast} <- [cast(info, field, value)], do: cast)

    # A scope result: a dynamic, `true` or `false`. Anything else is a bug.
    @spec checked!(term, String.t()) :: verdict
    def checked!(%Ecto.Query.DynamicExpr{} = dynamic, _where), do: dynamic
    def checked!(boolean, _where) when is_boolean(boolean), do: boolean

    def checked!(other, where) do
      raise Warden.PolicyError, """
      #{where} must return an Ecto dynamic, true or false, got: #{Info.shape(other)}\
      """
    end

    @spec both(verdict, verdict) :: verdict
    def both(false, _right), do: false
    def both(_left, false), do: false
    def both(true, right), do: right
    def both(left, true), do: left
    def both(left, right), do: dynamic(^left and ^right)

    @spec any(verdict, verdict) :: verdict
    def any(true, _right), do: true
    def any(_left, true), do: true
    def any(false, right), do: right
    def any(left, false), do: left
    def any(left, right), do: dynamic(^left or ^right)
  end
end
