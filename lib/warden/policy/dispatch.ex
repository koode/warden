defmodule Warden.Policy.Dispatch do
  @moduledoc false
  # Asks a policy module about values. Any module that implements the two entry points
  # below is a policy to `can/2,3`:
  #
  #   * `__warden_policy__(:info)` returns `%{authorizer: module, for: module,
  #     actions: [atom], tenant: atom | nil, system_kinds: [atom],
  #     enforces_binding: boolean}`;
  #   * `__warden_decide__(action, actor, values, context)` returns one
  #     `true | false | {:deny, reason}` per value, in order, or `{answers, actor}` to
  #     hand back the actor with what it cached (only its cache is kept).
  #
  # `use Warden.Policy` generates both (deciding through `allowed_many/4` or
  # `allowed?/4`). Before calling `__warden_decide__/4`, Warden denies `nil` values,
  # system actors of other kinds, and, for a bound credential, values of another tenant
  # (unless the policy sets `enforces_binding: true` and applies the binding itself, as a
  # query scope can). The result is checked here, so every implementation fails closed
  # the same way.

  alias Warden.{Actor, Evaluator, Shape}
  alias Warden.Authorizer.Callbacks

  @spec info!(term) :: map
  def info!(policy) when is_atom(policy) do
    if Code.ensure_loaded?(policy) and function_exported?(policy, :__warden_policy__, 1) and
         function_exported?(policy, :__warden_decide__, 4) do
      policy.__warden_policy__(:info)
    else
      raise Warden.PolicyError, "#{inspect(policy)} is not a Warden policy (use Warden.Policy)"
    end
  end

  def info!(other),
    do: raise(Warden.PolicyError, "not a Warden policy: #{Shape.describe(other)}")

  # The default `__warden_decide__/4` of `use Warden.Policy`.
  @spec callbacks_decide(module, atom, Actor.t(), [term], map) :: term
  def callbacks_decide(policy, action, actor, values, context) do
    if function_exported?(policy, :allowed_many, 4),
      do: policy.allowed_many(action, actor, values, context),
      else: Enum.map(values, &policy.allowed?(action, actor, &1, context))
  end

  # Returns one verdict (`:ok | {:deny, reason}`) per value, and the actor with what the
  # policy cached in it (tenant roles, tenants).
  @spec decide(module, atom, Actor.t(), [term], map, module) ::
          {[:ok | {:deny, term}], Actor.t()}
  def decide(policy, action, %Actor{} = actor, values, context, authorizer) do
    info = info!(policy)
    ensure_usable!(policy, info, action, authorizer)

    screened = Enum.map(values, &screen(&1, actor, info, authorizer))
    asked = for {:ask, value} <- screened, do: value
    {answers, actor} = ask(policy, action, actor, asked, context)
    verdicts = merge(screened, answers, [])
    {verdicts, actor}
  end

  defp ensure_usable!(policy, info, action, authorizer) do
    cond do
      info.authorizer != authorizer ->
        raise Warden.PolicyError, """
        #{inspect(policy)} belongs to #{inspect(info.authorizer)}, but the rule is \
        evaluated with #{inspect(authorizer)}\
        """

      action not in info.actions ->
        raise Warden.PolicyError, """
        #{inspect(policy)} has no action #{inspect(action)} (actions: \
        #{inspect(info.actions)})\
        """

      true ->
        :ok
    end
  end

  # `{:ask, value}` or a verdict decided without calling the policy.
  defp screen(nil, _actor, _info, _authorizer), do: {:deny, nil}

  defp screen(value, actor, info, authorizer) do
    cond do
      actor.system? and Actor.kind(actor) not in info.system_kinds -> {:deny, nil}
      not binding_allows?(value, actor, info, authorizer) -> {:deny, :tenant_binding}
      true -> {:ask, value}
    end
  end

  defp binding_allows?(value, actor, info, authorizer) do
    case Actor.bound_tenant(actor) do
      nil -> true
      _bound when info.enforces_binding -> true
      bound -> value_tenant(value, info, authorizer) == bound
    end
  end

  # The tenant of a value for a policy: the authorizer's `tenant_of/1` when defined, else
  # the policy's `tenant:` field, else the default lookup.
  @spec value_tenant(term, map, module) :: term
  def value_tenant(value, info, authorizer) do
    cond do
      function_exported?(authorizer, :tenant_of, 1) -> authorizer.tenant_of(value)
      info.tenant != nil and is_map(value) -> Map.get(value, info.tenant)
      true -> Callbacks.tenant_of(authorizer, value)
    end
  end

  defp ask(_policy, _action, actor, [], _context), do: {[], actor}

  defp ask(policy, action, actor, values, context) do
    count = length(values)

    returned =
      try do
        policy.__warden_decide__(action, actor, values, context)
      rescue
        # A policy layer built on Warden (Warden.Ecto.Policy) reports its own contract
        # errors, which already name shapes only.
        error in Warden.PolicyError -> reraise error, __STACKTRACE__
      catch
        kind, reason -> decide_failed!(policy, action, kind, reason)
      end

    {answers, actor} = with_cache(returned, actor)

    if is_list(answers) and length(answers) == count do
      verdicts = Enum.map(answers, &verdict!(&1, policy, action))
      {verdicts, actor}
    else
      raise Warden.PolicyError, """
      #{inspect(policy)} must return one result per value for #{inspect(action)} \
      (#{count} values), got: #{Shape.describe(answers)}\
      """
    end
  end

  # An implementation may return `{answers, actor}` to hand back what it cached while
  # deciding. Only the cache is taken from that actor: who the actor is never changes.
  defp with_cache({answers, %Actor{cache: cache}}, actor),
    do: {answers, %{actor | cache: Map.merge(actor.cache, cache)}}

  defp with_cache(answers, actor), do: {answers, actor}

  @spec decide_failed!(module, atom, atom, term) :: no_return()
  defp decide_failed!(policy, action, kind, reason) do
    raise Warden.PolicyError, """
    #{inspect(policy)} failed deciding #{inspect(action)}, so nothing is allowed: \
    #{Shape.failure(kind, reason)}\
    """
  end

  defp verdict!(true, _policy, _action), do: :ok
  defp verdict!(false, _policy, _action), do: {:deny, nil}

  defp verdict!({:deny, reason} = denial, policy, action) do
    if Evaluator.valid_reason?(reason), do: denial, else: bad_answer!(denial, policy, action)
  end

  defp verdict!(other, policy, action), do: bad_answer!(other, policy, action)

  @spec bad_answer!(term, module, atom) :: no_return()
  defp bad_answer!(answer, policy, action) do
    raise Warden.PolicyError, """
    #{inspect(policy)} must return true, false or {:deny, reason} for \
    #{inspect(action)}, got: #{Shape.describe(answer)}\
    """
  end

  defp merge([], [], acc), do: Enum.reverse(acc)

  defp merge([{:ask, _value} | rest], [answer | answers], acc),
    do: merge(rest, answers, [answer | acc])

  defp merge([verdict | rest], answers, acc), do: merge(rest, answers, [verdict | acc])
end
