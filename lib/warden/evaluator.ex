defmodule Warden.Evaluator do
  @moduledoc false
  # Evaluates rules. Every front end (the core API, `Warden.Plug`, Absinthe) goes through
  # here, so the semantics are the same everywhere:
  #
  #   * only a literal `true` from a check grants; `false` and `{:deny, reason}` deny;
  #     anything else raises `Warden.PolicyError`;
  #   * a system actor passes no `authenticated()`, role, tenant role, permission or
  #     credential rule, and no check unless the check names its kind;
  #   * a delegated actor is evaluated twice, for itself and for its delegator, and the
  #     results are ANDed;
  #   * the actor's tenant-role cache is threaded through the evaluation and the updated
  #     actor is returned, so callers can keep it.
  #
  # An outcome is `:ok` or `{:deny, failed_rule, missing_roles, missing_permissions,
  # reason}`. `trace` collects `{leaf_rule, :ok | {:deny, reason}}` in evaluation order.

  alias Warden.{Actor, Check, Credential, Explanation, Shape}
  alias Warden.Authorizer.{Callbacks, Catalog}
  alias Warden.Policy.Dispatch

  @unavailable :unavailable
  @tenant_binding :tenant_binding
  @check_contract "must return true or false (or {:deny, reason})"

  defstruct [
    :authorizer,
    :catalog,
    :check,
    explain?: false,
    trace: [],
    tenant: nil,
    decided: %{},
    foreign?: nil
  ]

  @type outcome :: :ok | {:deny, term, [atom], [term], term}
  @type failure :: %{
          failed_rule: term,
          missing_roles: [atom],
          missing_permissions: [term],
          reason: term,
          trace: [{term, :ok | {:deny, term}}]
        }

  # One rule for one check. Returns the result, the updated actor and the first tenant
  # the evaluation resolved (for telemetry).
  @spec one(term, Check.t(), module) :: {:ok | {:deny, failure}, Actor.t(), term}
  def one(rule, %Check{actor: %Actor{}} = check, authorizer) do
    {outcome, state} = run(rule, check, authorizer, %{})
    actor = state.check.actor
    trace = Enum.reverse(state.trace)

    case {outcome, actor.delegator} do
      {:ok, %Actor{} = delegator} ->
        {delegated, delegator_state} = run(rule, %{check | actor: delegator}, authorizer, %{})
        actor = %{actor | delegator: delegator_state.check.actor}
        trace = trace ++ Enum.reverse(delegator_state.trace)
        result = result(delegated, trace)
        {result, actor, state.tenant || delegator_state.tenant}

      _single_or_denied ->
        result = result(outcome, trace)
        {result, actor, state.tenant}
    end
  end

  # One rule for many checks that share one actor (`Warden.filter/4`, GraphQL lists).
  # Batched leaves (checks declared with `batch: true`) are decided first, once for all
  # values; then the rule is evaluated per value from those results, short-circuiting
  # over the other leaves as `one/3` does. A delegated actor's delegator is asked only
  # about the values the actor passed. Returns the results in order and the updated
  # actor (`nil` for no checks).
  @spec many(term, [Check.t()], module) :: {[:ok | {:deny, failure}], Actor.t() | nil}
  def many(_rule, [], _authorizer), do: {[], nil}

  def many(rule, [%Check{actor: %Actor{} = actor} | _rest] = checks, authorizer) do
    {results, actor} = many_pass(rule, checks, actor, authorizer)

    case actor.delegator do
      nil ->
        {results, actor}

      %Actor{} = delegator ->
        {results, delegator} = delegated_pass(rule, checks, results, delegator, authorizer)
        {results, %{actor | delegator: delegator}}
    end
  end

  defp delegated_pass(rule, checks, results, delegator, authorizer) do
    passed = for {check, :ok} <- Enum.zip(checks, results), do: check
    {delegated, delegator} = many_pass(rule, passed, delegator, authorizer)
    merged = merge_delegated(results, delegated, [])
    {merged, delegator}
  end

  defp merge_delegated([], _delegated, acc), do: Enum.reverse(acc)

  defp merge_delegated([:ok | rest], [delegated | more], acc),
    do: merge_delegated(rest, more, [delegated | acc])

  defp merge_delegated([denied | rest], delegated, acc),
    do: merge_delegated(rest, delegated, [denied | acc])

  defp many_pass(_rule, [], actor, _authorizer), do: {[], actor}

  defp many_pass(rule, checks, actor, authorizer) do
    catalog = authorizer.__warden_catalog__()

    # A bound actor's batch callbacks never see values of another tenant: those values
    # deny with :tenant_binding before the batch, as they do per value.
    foreign = Enum.map(checks, &foreign_tenant?(%{&1 | actor: actor}, authorizer))
    asked = for {check, false} <- Enum.zip(checks, foreign), do: check

    tables =
      for leaf <- batched_leaves(rule, catalog, []),
          not leaf_refused?(leaf, actor, catalog),
          do: {leaf, leaf |> batch_verdicts(asked, actor, authorizer, catalog) |> spread(foreign)}

    checks
    |> Enum.with_index()
    |> Enum.map_reduce(actor, fn {check, index}, actor ->
      decided = Map.new(tables, fn {leaf, verdicts} -> {leaf, elem(verdicts, index)} end)
      {outcome, state} = run(rule, %{check | actor: actor}, authorizer, decided)
      result = result(outcome, Enum.reverse(state.trace))
      {result, state.check.actor}
    end)
  end

  # The `timeout:` of every check in the rule.
  @spec check_timeouts(term, map) :: [pos_integer]
  def check_timeouts({tag, rules}, catalog) when tag in [:all, :any] and is_list(rules),
    do: Enum.flat_map(rules, &check_timeouts(&1, catalog))

  def check_timeouts({:check, name, _opts}, catalog) do
    case check_spec(catalog, name).timeout do
      nil -> []
      timeout -> [timeout]
    end
  end

  def check_timeouts(_rule, _catalog), do: []

  # True when the rule has a leaf that is decided for many values at once.
  @spec batched?(term, map) :: boolean
  def batched?(rule, catalog), do: batched_leaves(rule, catalog, []) != []

  # The distinct batched leaves of a rule, in rule order.
  defp batched_leaves({tag, rules}, catalog, acc) when tag in [:all, :any] and is_list(rules),
    do: Enum.reduce(rules, acc, &batched_leaves(&1, catalog, &2))

  defp batched_leaves({:check, name, _opts} = leaf, catalog, acc) do
    if check_spec(catalog, name).batch and leaf not in acc, do: acc ++ [leaf], else: acc
  end

  defp batched_leaves({:can, _policy, _action, opts} = leaf, _catalog, acc) when is_list(opts) do
    if Keyword.has_key?(opts, :arg) or leaf in acc, do: acc, else: acc ++ [leaf]
  end

  defp batched_leaves(_rule, _catalog, acc), do: acc

  defp leaf_refused?({:check, name, _opts}, actor, catalog),
    do: system_refused?(actor, check_spec(catalog, name))

  defp leaf_refused?({:can, _policy, _action, _opts}, _actor, _catalog), do: false

  # Puts the verdicts for the asked values back in place and denies the foreign ones.
  # Returns a tuple indexed like the checks.
  defp spread(verdicts, foreign), do: foreign |> spread(verdicts, []) |> List.to_tuple()

  defp spread([], _verdicts, acc), do: Enum.reverse(acc)

  defp spread([true | rest], verdicts, acc),
    do: spread(rest, verdicts, [{:deny, @tenant_binding} | acc])

  defp spread([false | rest], [verdict | verdicts], acc),
    do: spread(rest, verdicts, [verdict | acc])

  # Returns one verdict per check, in order. A policy is asked once about every value (it
  # splits by tenant itself); a batched check calls `check_many/2` once.
  defp batch_verdicts(_leaf, [], _actor, _authorizer, _catalog), do: []

  defp batch_verdicts(
         {:can, policy, action, _opts},
         [first | _rest] = checks,
         actor,
         authorizer,
         _catalog
       ) do
    values = Enum.map(checks, & &1.value)
    Dispatch.decide(policy, action, actor, values, first.context, authorizer)
  end

  defp batch_verdicts({:check, name, opts}, checks, actor, authorizer, catalog) do
    spec = check_spec(catalog, name)
    batch = Enum.map(checks, &%{&1 | actor: actor, name: name, opts: opts})
    count = length(batch)

    case caught(fn -> Callbacks.check_many(authorizer, name, batch) end, spec.timeout) do
      {:ok, results} -> batch_results!(results, count, authorizer, name)
      :timeout -> List.duplicate({:deny, @unavailable}, count)
      {:raised, kind, reason, _stacktrace} -> batch_raised!(kind, reason, authorizer, name)
    end
  end

  defp batch_results!(results, count, authorizer, name) when is_list(results) do
    if length(results) == count do
      Enum.map(results, &verdict!(&1, authorizer, name))
    else
      raise Warden.PolicyError, """
      #{inspect(authorizer)}.check_many(#{inspect(name)}, checks) returned \
      #{length(results)} results for #{count} checks\
      """
    end
  end

  defp batch_results!(other, _count, authorizer, name) do
    raise Warden.PolicyError, """
    #{inspect(authorizer)}.check_many(#{inspect(name)}, checks) must return a list, \
    got: #{Shape.describe(other)}\
    """
  end

  @spec batch_raised!(atom, term, module, atom) :: no_return()
  defp batch_raised!(kind, reason, authorizer, name) do
    raise Warden.PolicyError, """
    #{inspect(authorizer)}.check_many(#{inspect(name)}, checks) failed, so every value \
    is denied: #{Shape.failure(kind, reason)}\
    """
  end

  # Evaluates every sub-rule (no short-circuiting) and returns the full tree. The result
  # always equals the result of `one/3`: both reduce the same outcomes.
  @spec explain(term, Check.t(), module) :: {Explanation.t(), Actor.t()}
  def explain(rule, %Check{actor: %Actor{}} = check, authorizer) do
    {outcome, step, state} = check |> new_state(authorizer, %{}, true) |> eval_step(rule)
    actor = state.check.actor

    {delegator_explanation, actor} =
      case actor.delegator do
        nil ->
          {nil, actor}

        %Actor{} = delegator ->
          {explanation, delegator} = explain(rule, %{check | actor: delegator}, authorizer)
          {explanation, %{actor | delegator: delegator}}
      end

    explanation = %Explanation{
      result: explanation_result(outcome, delegator_explanation),
      reason: outcome_reason(outcome),
      steps: [step],
      delegator: delegator_explanation
    }

    {explanation, actor}
  end

  defp explanation_result(:ok, nil), do: :ok
  defp explanation_result(:ok, %Explanation{result: result}), do: result
  defp explanation_result(_denied, _delegator), do: :deny

  defp outcome_reason(:ok), do: nil
  defp outcome_reason({:deny, _failed, _roles, _perms, reason}), do: reason

  defp run(rule, check, authorizer, decided) do
    {outcome, _step, state} = check |> new_state(authorizer, decided, false) |> eval_step(rule)
    {outcome, state}
  end

  defp new_state(check, authorizer, decided, explain?) do
    %__MODULE__{
      authorizer: authorizer,
      catalog: authorizer.__warden_catalog__(),
      check: check,
      decided: decided,
      explain?: explain?
    }
  end

  defp result(:ok, _trace), do: :ok

  defp result({:deny, failed, roles, perms, reason}, trace) do
    failure = %{
      failed_rule: failed,
      missing_roles: Enum.uniq(roles),
      missing_permissions: Enum.uniq(perms),
      reason: reason,
      trace: trace
    }

    {:deny, failure}
  end

  # Returns {outcome, explain_step | nil, state}.
  defp eval_step(state, {:all, [_ | _] = rules} = rule) do
    {outcome, steps, state} = eval_all(rules, state, :ok, [])
    {outcome, step(state, rule, outcome, steps), state}
  end

  defp eval_step(state, {:any, [_ | _] = rules} = rule) do
    {outcome, steps, state} = eval_any(rules, rule, state, {:deny, rule, [], [], []}, [])
    {outcome, step(state, rule, outcome, steps), state}
  end

  defp eval_step(state, rule) do
    {outcome, state} = screened_leaf(rule, state)
    entry = {rule, trace_outcome(outcome)}
    state = %{state | trace: [entry | state.trace]}
    {outcome, step(state, rule, outcome, []), state}
  end

  defp step(%__MODULE__{explain?: false}, _rule, _outcome, _steps), do: nil

  defp step(%__MODULE__{explain?: true}, rule, outcome, steps) do
    %{rule: rule, result: trace_outcome(outcome), steps: steps}
  end

  defp trace_outcome(:ok), do: :ok
  defp trace_outcome({:deny, _failed, _roles, _perms, reason}), do: {:deny, reason}

  # `all_of`: the first denial is the outcome. Short-circuits unless explaining.
  defp eval_all([], state, outcome, steps), do: {outcome, Enum.reverse(steps), state}

  defp eval_all([rule | rest], state, outcome, steps) do
    {child, step, state} = eval_step(state, rule)
    outcome = if outcome == :ok, do: child, else: outcome
    steps = [step | steps]

    if outcome != :ok and not state.explain?,
      do: {outcome, Enum.reverse(steps), state},
      else: eval_all(rest, state, outcome, steps)
  end

  # `any_of`: passes at the first pass. A denial names the `any_of` rule, every missing
  # role and permission, and the reasons of the branches in rule order.
  defp eval_any([], _rule, state, {:deny, failed, roles, perms, reasons}, steps),
    do: {{:deny, failed, roles, perms, Enum.reverse(reasons)}, Enum.reverse(steps), state}

  defp eval_any([], _rule, state, :ok, steps), do: {:ok, Enum.reverse(steps), state}

  defp eval_any([rule | rest], any_rule, state, outcome, steps) do
    {child, step, state} = eval_step(state, rule)
    steps = [step | steps]
    outcome = merge_any(outcome, child)

    if outcome == :ok and not state.explain?,
      do: {:ok, Enum.reverse(steps), state},
      else: eval_any(rest, any_rule, state, outcome, steps)
  end

  defp merge_any(:ok, _child), do: :ok
  defp merge_any(_denied, :ok), do: :ok

  defp merge_any(
         {:deny, failed, roles, perms, reasons},
         {:deny, _rule, more_roles, more_perms, reason}
       ),
       do: {:deny, failed, roles ++ more_roles, perms ++ more_perms, [reason | reasons]}

  # A bound actor (a credential or system actor with a tenant) denies every leaf but
  # `public()` and `covered()` for a value of another known tenant, before any user code
  # runs. A value without a known tenant goes on to the leaf.
  defp screened_leaf(rule, state) when rule in [:public, :covered], do: leaf(rule, state)

  defp screened_leaf(rule, state) do
    state = with_foreign(state)

    if state.foreign?,
      do: {{:deny, rule, [], [], @tenant_binding}, state},
      else: leaf(rule, state)
  end

  defp with_foreign(%__MODULE__{foreign?: nil} = state),
    do: %{state | foreign?: foreign_tenant?(state.check, state.authorizer)}

  defp with_foreign(state), do: state

  # True when the actor is bound and the value's tenant is known and another one.
  @spec foreign_tenant?(Check.t(), module) :: boolean
  def foreign_tenant?(%Check{actor: actor, value: value}, authorizer) do
    case Actor.bound_tenant(actor) do
      nil -> false
      bound -> value_tenant(value, authorizer) not in [nil, bound]
    end
  end

  defp value_tenant(nil, _authorizer), do: nil
  defp value_tenant(value, authorizer), do: authorizer |> Callbacks.tenant_of(value) |> scalar()

  # A tenant is a scalar (an id); a list, map or tuple is never one.
  defp scalar(tenant) when is_list(tenant) or is_map(tenant) or is_tuple(tenant), do: nil
  defp scalar(tenant), do: tenant

  defp leaf(rule, state) when rule in [:public, :covered], do: {:ok, state}
  defp leaf(:deny, state), do: deny(:deny, state)

  defp leaf(:authenticated, %__MODULE__{check: %Check{actor: actor}} = state) do
    if Actor.anonymous?(actor) or actor.system?,
      do: deny(:authenticated, state),
      else: {:ok, state}
  end

  defp leaf({:role, role} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    if user_with?(actor, &MapSet.member?(&1.roles, role)),
      do: {:ok, state},
      else: deny(rule, [role], [], state)
  end

  defp leaf({:any_role, roles} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    if user_with?(actor, fn actor -> Enum.any?(roles, &MapSet.member?(actor.roles, &1)) end),
      do: {:ok, state},
      else: deny(rule, roles, [], state)
  end

  defp leaf({:permission, perm} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    if user_with?(actor, &has_permission?(&1, perm)),
      do: {:ok, state},
      else: deny(rule, [], [perm], state)
  end

  defp leaf({:all_permissions, perms} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    missing = if actor.system?, do: perms, else: Enum.reject(perms, &has_permission?(actor, &1))

    case missing do
      [] -> {:ok, state}
      missing -> deny(rule, [], missing, state)
    end
  end

  defp leaf({:any_permission, perms} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    if user_with?(actor, fn actor -> Enum.any?(perms, &has_permission?(actor, &1)) end),
      do: {:ok, state},
      else: deny(rule, [], perms, state)
  end

  defp leaf({:kind, kinds} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    if Actor.kind(actor) in kinds, do: {:ok, state}, else: deny(rule, state)
  end

  defp leaf(:session, %__MODULE__{check: %Check{actor: actor}} = state) do
    if credentialed?(actor) and Credential.session?(actor.credential),
      do: {:ok, state},
      else: deny(:session, state)
  end

  defp leaf({:credential_scope, scope} = rule, %__MODULE__{check: %Check{actor: actor}} = state) do
    if credentialed?(actor) and Credential.grants?(actor.credential, scope),
      do: {:ok, state},
      else: deny(rule, state)
  end

  defp leaf({:tenant_role, role, opts} = rule, %__MODULE__{} = state) when is_list(opts) do
    %Check{actor: actor} = check = state.check

    if actor.system? or Actor.anonymous?(actor) do
      deny(rule, state)
    else
      tenant = rule_tenant(Keyword.get(opts, :tenant, :value), check, state.authorizer)
      state = note_tenant(state, tenant)
      {roles, actor} = Actor.tenant_roles(actor, tenant, check.context, state.authorizer)
      state = put_actor(state, actor)

      if MapSet.member?(roles, role), do: {:ok, state}, else: deny(rule, state)
    end
  end

  defp leaf({:check, name, opts} = rule, %__MODULE__{} = state) when is_atom(name) do
    spec = check_spec(state.catalog, name)

    cond do
      system_refused?(state.check.actor, spec) ->
        deny(rule, state)

      Map.has_key?(state.decided, rule) ->
        decided(Map.fetch!(state.decided, rule), rule, state)

      true ->
        check = %{state.check | name: name, opts: opts}
        verdict = call_check(state.authorizer, name, check, spec)
        decided(verdict, rule, state)
    end
  end

  defp leaf({:can, policy, action, opts} = rule, %__MODULE__{} = state) when is_list(opts) do
    if Map.has_key?(state.decided, rule) do
      decided(Map.fetch!(state.decided, rule), rule, state)
    else
      check = state.check
      values = can_values(policy, opts, check)
      verdict = can_verdict(policy, action, values, check, state.authorizer)
      decided(verdict, rule, state)
    end
  end

  defp leaf(other, _state) do
    raise Warden.PolicyError, "invalid rule: #{inspect(other)}"
  end

  # The values a `can` rule asks about: the guarded value, or `{schema, id}` for every id
  # at the `arg:` path (a list of ids asks about each). Nothing to ask about denies.
  defp can_values(policy, opts, %Check{} = check) do
    case Keyword.fetch(opts, :arg) do
      :error ->
        List.wrap(check.value)

      {:ok, path} ->
        schema = Dispatch.info!(policy).for
        ids = check.args |> get_path(path) |> List.wrap()

        # A nil id is never asked about; it denies the whole rule.
        if nil in ids, do: [], else: Enum.map(ids, &{schema, &1})
    end
  end

  defp can_verdict(_policy, _action, [], _check, _authorizer), do: {:deny, nil}

  defp can_verdict(policy, action, values, check, authorizer) do
    policy
    |> Dispatch.decide(action, check.actor, values, check.context, authorizer)
    |> Enum.find(:ok, &(&1 != :ok))
  end

  # A verdict is `:ok` or `{:deny, reason}`.
  defp decided(:ok, _rule, state), do: {:ok, state}
  defp decided({:deny, reason}, rule, state), do: {{:deny, rule, [], [], reason}, state}

  defp deny(rule, state), do: deny(rule, [], [], state)
  defp deny(rule, roles, perms, state), do: {{:deny, rule, roles, perms, nil}, state}

  # Roles and permissions belong to users: a system actor never has any.
  defp user_with?(%Actor{system?: true}, _fun), do: false
  defp user_with?(%Actor{} = actor, fun), do: fun.(actor)

  # Credential rules need a credential holder: an anonymous actor has no session, and a
  # system actor's credential is not a session and grants no scopes.
  defp credentialed?(%Actor{} = actor), do: not Actor.anonymous?(actor)

  defp has_permission?(%Actor{permissions: perms}, perm) do
    MapSet.member?(perms, :all) or MapSet.member?(perms, perm)
  end

  defp put_actor(%__MODULE__{check: check} = state, actor),
    do: %{state | check: %{check | actor: actor}}

  defp note_tenant(%__MODULE__{tenant: nil} = state, tenant), do: %{state | tenant: tenant}
  defp note_tenant(state, _tenant), do: state

  # The tenant a tenant-role rule asks about.
  @spec rule_tenant(term, Check.t(), module) :: term
  def rule_tenant(:value, %Check{value: value}, authorizer), do: value_tenant(value, authorizer)

  def rule_tenant({:arg, path}, %Check{args: args}, _authorizer),
    do: args |> get_path(path) |> scalar()

  # Reads `path` (atoms and list indexes) from argument maps. Missing keys give `nil`.
  @spec get_path(term, [atom | non_neg_integer]) :: term
  def get_path(value, []), do: value
  def get_path(map, [key | rest]) when is_map(map), do: map |> Map.get(key) |> get_path(rest)

  def get_path(list, [index | rest]) when is_list(list) and is_integer(index),
    do: list |> Enum.at(index) |> get_path(rest)

  def get_path(_value, _path), do: nil

  @spec check_spec(map, atom) :: map
  def check_spec(catalog, name) do
    catalog
    |> Map.get(:check_specs, %{})
    |> Map.get(name, Catalog.default_check_spec())
  end

  # A system actor reaches a check only when the check names its kind.
  @spec system_refused?(Actor.t(), map) :: boolean
  def system_refused?(%Actor{system?: true, kind: kind}, %{system_kinds: kinds}),
    do: kind not in kinds

  def system_refused?(%Actor{}, _spec), do: false

  defp call_check(authorizer, name, check, spec) do
    case with_timeout(fn -> single_check(authorizer, name, check, spec) end, spec.timeout) do
      {:ok, result} -> verdict!(result, authorizer, name)
      :timeout -> {:deny, @unavailable}
      {:raised, kind, reason, stacktrace} -> :erlang.raise(kind, reason, stacktrace)
    end
  end

  # A batched check answers a single value through check_many/2 with one element, unless
  # it declares `single: true`, which routes single values to check/2.
  defp single_check(authorizer, name, check, %{batch: true, single: false}),
    do: single_from_many(authorizer, name, check)

  defp single_check(authorizer, name, check, _spec), do: Callbacks.check(authorizer, name, check)

  defp single_from_many(authorizer, name, check) do
    case run_caught(fn -> Callbacks.check_many(authorizer, name, [check]) end) do
      {:ok, [result]} ->
        result

      {:raised, kind, reason, _stacktrace} ->
        batch_raised!(kind, reason, authorizer, name)

      {:ok, other} ->
        raise Warden.PolicyError, """
        #{inspect(authorizer)}.check_many(#{inspect(name)}, checks) must return one result \
        per check, got: #{Shape.describe(other)}\
        """
    end
  end

  # Turns a check result into a verdict. Only `true` grants.
  @spec verdict!(term, module, atom) :: :ok | {:deny, term}
  def verdict!(true, _authorizer, _name), do: :ok
  def verdict!(false, _authorizer, _name), do: {:deny, nil}

  def verdict!({:deny, reason} = denial, authorizer, name) do
    if valid_reason?(reason), do: denial, else: bad_result!(denial, authorizer, name)
  end

  def verdict!(other, authorizer, name), do: bad_result!(other, authorizer, name)

  @spec bad_result!(term, module, atom) :: no_return()
  defp bad_result!(result, authorizer, name) do
    raise Warden.PolicyError,
          "#{inspect(authorizer)}.check(#{inspect(name)}, ...) #{@check_contract}, got: #{Shape.describe(result)}"
  end

  @spec valid_reason?(term) :: boolean
  def valid_reason?(reason) when is_atom(reason), do: true
  def valid_reason?({reason, details}) when is_atom(reason) and is_map(details), do: true
  def valid_reason?(_reason), do: false

  # Runs `fun` in a separate process when `timeout` (ms) is set. Returns `{:ok, result}`,
  # `:timeout` (the process is killed) or `{:raised, kind, reason, stacktrace}`. The
  # process carries the caller chain, so test sandboxes that follow `$callers` see it.
  @spec with_timeout((-> term), pos_integer | nil) ::
          {:ok, term} | :timeout | {:raised, atom, term, list}
  def with_timeout(fun, nil), do: {:ok, fun.()}

  def with_timeout(fun, timeout) when is_integer(timeout) do
    parent = self()
    ref = make_ref()
    callers = [parent | Process.get(:"$callers", [])]
    dictionary = inherited_dictionary()

    {pid, monitor} =
      spawn_monitor(fn ->
        Enum.each(dictionary, fn {key, value} -> Process.put(key, value) end)
        Process.put(:"$callers", callers)
        send(parent, {ref, run_caught(fun)})
      end)

    receive do
      {^ref, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^pid, reason} ->
        {:raised, :exit, reason, []}
    after
      timeout ->
        Process.exit(pid, :kill)
        await_down(monitor, pid)
        flush_reply(ref)
        :timeout
    end
  end

  # Batch callbacks never raise past Warden: a raise becomes a `Warden.PolicyError`.
  defp caught(fun, nil), do: run_caught(fun)
  defp caught(fun, timeout), do: with_timeout(fun, timeout)

  defp run_caught(fun) do
    {:ok, fun.()}
  catch
    kind, reason -> {:raised, kind, reason, __STACKTRACE__}
  end

  # The caller's process dictionary, so a check reads the same process state (a tenant
  # prefix, a dynamic repo) with or without a timeout. Keys that are atoms starting with
  # `$` belong to the runtime and are not copied; `$callers` is set separately.
  defp inherited_dictionary do
    for {key, value} <- Process.get(), not runtime_key?(key), do: {key, value}
  end

  defp runtime_key?(key) when is_atom(key),
    do: key |> Atom.to_string() |> String.starts_with?("$")

  defp runtime_key?(_key), do: false

  # After the kill the process is gone only once `:DOWN` arrives; a reply it sent before
  # that is flushed next, so none can arrive late.
  defp await_down(monitor, pid) do
    receive do
      {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
    end
  end

  defp flush_reply(ref) do
    receive do
      {^ref, _late} -> :ok
    after
      0 -> :ok
    end
  end
end
