# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Middleware do
    @moduledoc false
    # The two middleware entries Warden attaches to fields.
    #
    #   * `pre/2` runs first: the parent object rule, the effective field rule and the
    #     argument / input-field rules. On denial the resolver and the rest of the chain do
    #     not run.
    #   * `post/2` runs last: the object rules of the resolved value, per list item.
    #
    # Both are attached by `Warden.Absinthe.Phase.Attach` at schema compile time.

    alias Absinthe.Middleware.Batch
    alias Absinthe.Resolution
    alias Absinthe.Type.{Interface, Union}
    alias Warden.Absinthe.Decide
    alias Warden.{Actor, Check, Denial, Evaluator, Shape}
    alias Warden.Authorizer.Callbacks
    alias Warden.Fields.Redactor

    @acc_key Warden
    @decided :__warden_decided__

    def pre_spec(spec), do: {{__MODULE__, :pre}, spec}
    def post_spec(spec), do: {{__MODULE__, :post}, spec}
    def shim_spec(shim_args, post), do: {{__MODULE__, :shim}, {shim_args, post}}

    def warden_entry?({{__MODULE__, _}, _}), do: true
    def warden_entry?(_), do: false

    # The actor is built once per document execution and cached in `resolution.acc`.
    # Evaluations return it with the tenant roles they read; `put_actor/2` stores that
    # back, so `tenant_roles/3` runs at most once per tenant per execution.
    def actor(%Resolution{acc: acc, context: context} = res, authorizer) do
      case acc do
        %{@acc_key => %{actor: %Actor{} = actor}} ->
          {actor, res}

        _ ->
          actor = Actor.build(authorizer, context)
          {actor, put_actor(res, actor)}
      end
    end

    # What cross-parent batching shares per document execution, made once and kept in
    # `resolution.acc`: a reference that groups the deferred checks of one execution, and
    # the actor and the context encoded as one binary. Absinthe runs the batch function in
    # another process, and a message copies a term once per reference to it; a large
    # binary is shared instead, so every deferred check costs the same whatever the size
    # of the context or the subject.
    def execution_share(%Resolution{acc: acc} = res, %Actor{} = actor) do
      state = Map.get(acc, @acc_key, %{})

      case state do
        %{execution: share} ->
          {share, res}

        _none ->
          shared = :erlang.term_to_binary({actor, res.context})
          share = {make_ref(), shared}
          {share, %{res | acc: Map.put(acc, @acc_key, Map.put(state, :execution, share))}}
      end
    end

    def put_actor(%Resolution{acc: acc} = res, %Actor{} = actor) do
      state = Map.get(acc, @acc_key, %{})
      %{res | acc: Map.put(acc, @acc_key, Map.put(state, :actor, actor))}
    end

    def pre(%Resolution{} = res, %{authorizer: authorizer, checks: checks} = spec) do
      {actor, res} = actor(res, authorizer)

      base = %Check{
        actor: actor,
        value: res.source,
        args: res.arguments || %{},
        context: res.context,
        field: field_ident(res),
        parent_type: parent_ident(res),
        resolution: res
      }

      run = skip_admitted(checks, res, actor)
      {verdict, actor} = run_checks(run, base, authorizer)
      res = put_actor(res, actor)

      case verdict do
        :ok ->
          emit(:field, checks, actor, nil)
          res

        {:deny, kind, rule, failure, extra} ->
          denial =
            struct!(
              Denial,
              [
                kind: kind,
                rule: rule,
                failed_rule: failure.failed_rule,
                missing_roles: failure.missing_roles,
                missing_permissions: failure.missing_permissions,
                reason: failure.reason,
                trace: failure.trace,
                actor: actor,
                path: Resolution.path(res),
                field: base.field,
                parent_type: base.parent_type
              ] ++ extra
            )

          emit(kind, rule, actor, denial)
          apply_pre_denial(res, denial, authorizer, Map.get(spec, :on_deny, :error))
      end
    end

    # The parent object rule is decided again for every field (defense in depth), except
    # for a value the post middleware of this execution already admitted under a batched
    # rule: re-deciding it per field would undo the batching. Admissions are keyed by the
    # type, the actor and the exact value, so another actor or a changed value is decided
    # again.
    defp skip_admitted([{:object, type, _rule} | rest] = checks, res, actor) do
      if admitted?(res, type, actor, res.source), do: rest, else: checks
    end

    defp skip_admitted(checks, _res, _actor), do: checks

    defp admitted?(%Resolution{acc: acc}, type, actor, value) do
      key = admission_key(type, actor, value)

      acc
      |> Map.get(@acc_key, %{})
      |> Map.get(:admitted, %{})
      |> Map.get(:erlang.phash2(key), [])
      |> Enum.member?(key)
    end

    defp admission_key(type, actor, value), do: {type, without_cache(actor), value}

    defp put_admitted(res, [], _actor), do: res

    defp put_admitted(%Resolution{acc: acc} = res, admitted, actor) do
      state = Map.get(acc, @acc_key, %{})

      table =
        Enum.reduce(admitted, Map.get(state, :admitted, %{}), fn {type, value}, table ->
          key = admission_key(type, actor, value)
          Map.update(table, :erlang.phash2(key), [key], &[key | &1])
        end)

      %{res | acc: Map.put(acc, @acc_key, Map.put(state, :admitted, table))}
    end

    defp emit(kind, rule, actor, denial) do
      decision = %{
        layer: :absinthe,
        kind: kind,
        rule: emitted_rule(rule),
        actor: actor,
        denied: if(denial, do: 1, else: 0),
        reason: denial && denial.reason
      }

      Warden.Telemetry.decision(decision)
    end

    # A passing pre entry reports the rules it ran.
    defp emitted_rule(checks) when is_list(checks), do: Enum.map(checks, &check_rule_term/1)
    defp emitted_rule(rule), do: rule

    defp check_rule_term({:object, _type, rule}), do: rule
    defp check_rule_term({:field, rule}), do: rule
    defp check_rule_term({:introspection, rule}), do: rule
    defp check_rule_term({:args, %{args: args}}), do: {:args, Enum.map(args, &elem(&1, 0))}

    # Shared with subscribe-time checks. Returns {verdict, actor}: the verdict is :ok or
    # {:deny, kind, rule, failure, extra_denial_fields}, the actor carries the tenant
    # roles the checks read.
    def run_checks(checks, %Check{} = base, authorizer) do
      {verdict, base} =
        first_denial(checks, base, fn check, base -> run_check(check, base, authorizer) end)

      {verdict, base.actor}
    end

    # Evaluates `rule` for `check`; returns {:ok | {:deny, failure}, check with the
    # updated actor}.
    defp evaluate(rule, %Check{} = check, authorizer) do
      {result, actor, _tenant} = Evaluator.one(rule, check, authorizer)
      {result, %{check | actor: actor}}
    end

    defp run_check({:object, type, rule}, base, authorizer) do
      case evaluate(rule, %{base | type: type}, authorizer) do
        {:ok, check} -> {:ok, %{check | type: base.type}}
        {{:deny, failure}, check} -> {{:deny, :object, rule, failure, [type: type]}, check}
      end
    end

    defp run_check({:field, rule}, base, authorizer) do
      case evaluate(rule, base, authorizer) do
        {:ok, check} -> {:ok, check}
        {{:deny, failure}, check} -> {{:deny, :field, rule, failure, []}, check}
      end
    end

    defp run_check({:introspection, rule}, base, authorizer) do
      case evaluate(rule, base, authorizer) do
        {:ok, check} -> {:ok, check}
        {{:deny, failure}, check} -> {{:deny, :introspection, rule, failure, []}, check}
      end
    end

    defp run_check({:args, %{args: args, inputs: inputs}}, base, authorizer) do
      walk = %{inputs: inputs, base: base, authorizer: authorizer}

      {verdict, walk} =
        first_denial(args, walk, fn {ident, rule, defaults, specs}, walk ->
          check_entry(base.args, ident, {rule, defaults, specs}, [ident], walk)
        end)

      {verdict, walk.base}
    end

    # Runs `fun` on each item, threading `acc`, until one returns something other than
    # `:ok`. Returns {verdict, acc}.
    defp first_denial(items, acc, fun) do
      Enum.reduce_while(items, {:ok, acc}, fn item, {:ok, acc} ->
        case fun.(item, acc) do
          {:ok, acc} -> {:cont, {:ok, acc}}
          denied -> {:halt, denied}
        end
      end)
    end

    # An argument or input field is restricted when the client's value is present and:
    # there is no declared default (so any value, `null` included, is a choice the client
    # made), or it differs from any declared default.
    def restricted?(false, _value, _defaults), do: false
    def restricted?(true, _value, []), do: true
    def restricted?(true, value, defaults), do: Enum.any?(defaults, &(value !== &1))

    # Checks the argument or input field `key` of `map`, declared as
    # {rule, defaults, input_specs}. Returns {verdict, walk}.
    defp check_entry(map, key, declaration, path, walk) do
      check_input_value(Map.has_key?(map, key), Map.get(map, key), declaration, path, walk)
    end

    defp check_input_value(present?, value, {rule, defaults, specs}, path, walk) do
      case check_input_rule(present?, value, rule, defaults, path, walk) do
        {:ok, walk} -> first_denial(specs, walk, &walk_input(value, &1, path, &2))
        denied -> denied
      end
    end

    defp check_input_rule(present?, value, rule, defaults, path, walk) do
      if rule != nil and restricted?(present?, value, defaults),
        do: evaluate_input_rule(rule, path, walk),
        else: {:ok, walk}
    end

    defp evaluate_input_rule(rule, path, %{base: base, authorizer: authorizer} = walk) do
      case evaluate(rule, %{base | argument: path}, authorizer) do
        {:ok, check} ->
          {:ok, %{walk | base: %{check | argument: nil}}}

        {{:deny, failure}, check} ->
          {{:deny, :argument, rule, failure, [argument: path]}, %{walk | base: check}}
      end
    end

    defp walk_input(nil, _spec, _path, walk), do: {:ok, walk}
    defp walk_input(_value, nil, _path, walk), do: {:ok, walk}

    defp walk_input(value, {:non_null, spec}, path, walk),
      do: walk_input(value, spec, path, walk)

    defp walk_input(values, {:list, spec}, path, walk) when is_list(values) do
      values
      |> Enum.with_index()
      |> first_denial(walk, fn {value, index}, walk ->
        walk_input(value, spec, path ++ [index], walk)
      end)
    end

    # A single value given for a list input is coerced to a list by Absinthe; walk it as
    # an item in case a custom pipeline did not.
    defp walk_input(value, {:list, spec}, path, walk),
      do: walk_input(value, spec, path ++ [0], walk)

    defp walk_input(value, {:input, ident}, path, walk) when is_map(value) do
      walk.inputs
      |> Map.fetch!(ident)
      |> first_denial(walk, fn {field, rule, defaults, specs}, walk ->
        check_entry(value, field, {rule, defaults, specs}, path ++ [field], walk)
      end)
    end

    defp walk_input(_value, {:input, _ident}, _path, walk), do: {:ok, walk}

    defp apply_pre_denial(res, %Denial{kind: kind} = denial, authorizer, on_deny) do
      case pre_denial_result(authorizer, denial, on_deny) do
        {:error, term} ->
          res
          |> Resolution.put_result({:error, term})
          |> Map.put(:middleware, [])
          |> maybe_record_fold()

        :null ->
          maybe_record_fold(%{res | state: :resolved, value: nil, middleware: []})

        {:replace, value} when kind == :field ->
          # Object rules still apply to the replacement value.
          %{res | state: :resolved, value: value, middleware: post_only(res.middleware)}

        other ->
          raise Warden.PolicyError,
                "#{inspect(authorizer)}.deny/1 returned #{Shape.describe(other)} for a #{inspect(kind)} " <>
                  "denial; expected {:error, term} or :null" <>
                  if(kind == :field, do: " or {:replace, value}", else: "")
      end
    end

    # `authorize rule, on_deny: ...` decides the result of a field-rule denial itself;
    # every other denial goes through the authorizer's `deny/1`.
    defp pre_denial_result(_authorizer, %Denial{kind: :field}, :null), do: :null

    defp pre_denial_result(_authorizer, %Denial{kind: :field}, {:replace, _value} = result),
      do: result

    defp pre_denial_result(authorizer, denial, _on_deny), do: call_deny(authorizer, denial)

    defp post_only(middleware) do
      Enum.flat_map(middleware, fn
        {{__MODULE__, :post}, _} = post -> [post]
        {{__MODULE__, :shim}, {_, post}} -> [post_spec(post)]
        _ -> []
      end)
    end

    def call_deny(authorizer, %Denial{} = denial) do
      case Callbacks.deny(authorizer, denial) do
        {:error, _} = result ->
          result

        :null ->
          :null

        {:replace, _} = result ->
          result

        other ->
          raise Warden.PolicyError,
                "#{inspect(authorizer)}.deny/1 returned #{Shape.describe(other)}"
      end
    end

    ## Shim

    # Absinthe could not escape this field's middleware at compile time, so its shim
    # expands it at runtime and replaces the rest of the chain. Run it, then put Warden's
    # post middleware back at the end.
    def shim(%Resolution{} = res, {shim_args, post}) do
      res = Absinthe.Middleware.shim(res, shim_args)
      %{res | middleware: res.middleware ++ [post_spec(post)]}
    end

    ## Post

    # Middleware appended to the chain at runtime (after this entry was placed) would run
    # after the check and could change the value. Move the check behind it.
    def post(%Resolution{middleware: [_ | _] = rest} = res, spec) do
      %{res | middleware: rest ++ [post_spec(spec)]}
    end

    def post(
          %Resolution{state: :resolved, errors: [], value: value} = res,
          %{across_parents: true} = spec
        )
        when value != nil do
      if under_list?(res),
        do: defer_across_parents(res, spec),
        else: decide_and_walk(res, spec)
    end

    def post(%Resolution{state: :resolved, errors: []} = res, spec),
      do: decide_and_walk(res, spec)

    def post(res, _spec), do: res

    defp decide_and_walk(%Resolution{value: value} = res, spec) do
      {actor, res} = actor(res, spec.authorizer)

      base = %Check{
        actor: actor,
        args: res.arguments || %{},
        context: res.context,
        field: field_ident(res),
        parent_type: parent_ident(res),
        resolution: res
      }

      ctx = %{spec: spec, base: base, res: res, actor: actor}
      {decided, actor, stats} = Decide.decide(value, spec, ctx)
      res = res |> put_actor(actor) |> put_admitted(stats.admitted, actor)
      emit_post(spec, actor, stats)

      decided
      |> walk(spec.shape, %{ctx | res: res, actor: actor}, [])
      |> finish_post(res, spec)
    end

    defp under_list?(res), do: res |> Resolution.path() |> Enum.any?(&is_integer/1)

    # Cross-parent batching (`batch_across_parents: true`). The value's check is handed to
    # `Absinthe.Middleware.Batch`, which collects the checks of every parent at this level
    # and calls `decide_across_parents/2` once; `post_decided/2` then applies the outcome
    # exactly as the synchronous path would. Checks deferred this way have no
    # `resolution`, and tenant roles read in the batch are not kept in `resolution.acc`.
    defp defer_across_parents(%Resolution{value: value} = res, spec) do
      {actor, res} = actor(res, spec.authorizer)
      {execution, res} = execution_share(res, actor)
      rule = Map.fetch!(spec.rules, spec.named)

      # The actor and the context travel once per execution, in `execution`.
      base = %Check{
        value: value,
        args: res.arguments || %{},
        field: field_ident(res),
        parent_type: parent_ident(res),
        type: spec.named
      }

      ref = make_ref()
      redactor = spec |> Map.get(:redactors, %{}) |> Map.get(spec.named)
      batch_key = {__MODULE__, :decide_across_parents, {rule, spec.authorizer, redactor}}
      continuation = {{__MODULE__, :post_decided}, {spec, value}}

      waiting = %{
        res
        | state: :unresolved,
          value: nil,
          middleware: [continuation | res.middleware]
      }

      Batch.call(
        waiting,
        {batch_key, {ref, execution, base}, &{:ok, {:__warden_outcome__, Map.fetch!(&1, ref)}},
         batch_options(rule, spec.authorizer)}
      )
    end

    # Absinthe gives a batch function 5 s and then exits the document. A check with a
    # longer `timeout:` must deny with :unavailable instead, so the batch gets that
    # timeout plus a margin for the rest of the decision.
    @batch_margin 1_000
    @absinthe_batch_timeout 5_000

    defp batch_options(rule, authorizer) do
      longest =
        rule |> Evaluator.check_timeouts(authorizer.__warden_catalog__()) |> Enum.max(fn -> 0 end)

      timeout = max(@absinthe_batch_timeout, longest + @batch_margin)
      [timeout: timeout]
    end

    # Called by `Absinthe.Middleware.Batch` with the deferred checks of one level. Checks
    # are grouped by document execution (a batch may span several documents; one
    # execution has one actor and one context), by a reference kept in `resolution.acc`,
    # so grouping costs the same whatever the size of the context. Each group is decided
    # with one `Warden.Evaluator.many/3` call; with `redact_with`, the values that pass
    # are redacted together too. Returns `%{ref => {result, value}}`.
    def decide_across_parents({rule, authorizer, redactor}, items) do
      items
      |> Enum.group_by(
        fn {_ref, {execution, _shared}, _check} -> execution end,
        fn {ref, {_execution, shared}, check} -> {ref, shared, check} end
      )
      |> Enum.flat_map(fn {_execution, members} ->
        decide_group(rule, authorizer, redactor, members)
      end)
      |> Map.new()
    end

    defp decide_group(rule, authorizer, redactor, [{_ref, shared, _check} | _rest] = members) do
      {actor, context} = :erlang.binary_to_term(shared)
      refs = Enum.map(members, &elem(&1, 0))

      checks =
        Enum.map(members, fn {_ref, _shared, check} ->
          %{check | actor: actor, context: context}
        end)

      {results, actor} = Evaluator.many(rule, checks, authorizer)
      values = redact_passed(redactor, checks, results, actor, authorizer)
      denied = Enum.count(results, &(&1 != :ok))
      reason = Enum.find_value(results, fn result -> deny_reason(result) end)

      decision = %{
        layer: :absinthe,
        kind: :object,
        rule: rule,
        actor: actor,
        count: length(results),
        denied: denied,
        reason: reason
      }

      Warden.Telemetry.decision(decision)
      Enum.zip(refs, Enum.zip(results, values))
    end

    defp redact_passed(nil, checks, _results, _actor, _authorizer),
      do: Enum.map(checks, & &1.value)

    defp redact_passed(redactor, [first | _rest] = checks, results, actor, authorizer) do
      passed = for {check, :ok} <- Enum.zip(checks, results), do: check.value

      {redacted, _actor} =
        Redactor.redact_group(redactor, passed, actor, first.context, authorizer)

      merge_passed(checks, results, redacted)
    end

    defp merge_passed([], [], _redacted), do: []

    defp merge_passed([_check | checks], [:ok | results], [value | redacted]),
      do: [value | merge_passed(checks, results, redacted)]

    defp merge_passed([check | checks], [_denied | results], redacted),
      do: [check.value | merge_passed(checks, results, redacted)]

    defp deny_reason({:deny, %{reason: reason}}), do: reason
    defp deny_reason(_result), do: nil

    defp without_cache(%Actor{delegator: nil} = actor), do: %{actor | cache: %{}}

    defp without_cache(%Actor{delegator: delegator} = actor),
      do: %{actor | cache: %{}, delegator: without_cache(delegator)}

    # Resumes a deferred check: rebuilds the decided (and redacted) value and walks it like
    # `post/2`.
    def post_decided(
          %Resolution{value: {:__warden_outcome__, {result, value}}} = res,
          {spec, _original}
        ) do
      {actor, res} = actor(res, spec.authorizer)
      res = %{res | value: value}

      base = %Check{
        actor: actor,
        args: res.arguments || %{},
        context: res.context,
        field: field_ident(res),
        parent_type: parent_ident(res),
        resolution: res
      }

      ctx = %{spec: spec, base: base, res: res, actor: actor}
      outcome = Decide.outcome(result, Map.fetch!(spec.rules, spec.named), spec.named, ctx)
      res = if outcome == :ok, do: put_admitted(res, [{spec.named, value}], actor), else: res

      {@decided, value, outcome}
      |> walk(spec.shape, ctx, [])
      |> finish_post(res, spec)
    end

    # Anything else (an error the batch put on the field) fails closed: no value.
    def post_decided(%Resolution{} = res, _spec_and_value), do: %{res | value: nil}

    # One event per field resolution: a list is one decision over all its values.
    defp emit_post(_spec, _actor, %{count: 0}), do: :ok

    defp emit_post(spec, actor, stats) do
      decision = %{
        layer: :absinthe,
        kind: :object,
        rule: Map.get(spec.rules, spec.named) || spec.abstract_rule,
        actor: actor,
        count: stats.count,
        denied: stats.denied,
        reason: stats.reason
      }

      Warden.Telemetry.decision(decision)
    end

    defp finish_post({:ok, value, []}, res, _spec), do: %{res | value: value}

    defp finish_post({:ok, value, attached}, res, spec) do
      if innermost_non_null?(spec.shape) do
        # Absinthe's null propagation nulls the whole list field when a null appears at
        # any depth of a list whose innermost item type is non-null
        # (`null_allowed_in_list?/1` only looks at the innermost type). Report the errors
        # on the field so they are not lost.
        res
        |> null_field(Enum.map(attached, fn {_at, ii, term} -> {ii, term} end))
        |> maybe_record_fold()
      else
        record_item_errors(%{res | value: value}, attached)
      end
    end

    defp finish_post({tag, pending}, res, _spec) when tag in [:null, :bubble] do
      res |> null_field(pending) |> maybe_record_fold()
    end

    # Only produced inside lists; unreachable at the top level.
    defp finish_post(:filter, res, _spec), do: %{res | value: nil}

    defp finish_post({:fail_list, denial}, res, spec) do
      case call_deny(spec.authorizer, denial) do
        {:error, term} ->
          maybe_record_fold(%{res | value: nil, errors: [normalize_error!(term, spec)]})

        :null ->
          maybe_record_fold(%{res | value: nil})

        other ->
          object_replace_error!(spec, other)
      end
    end

    defp null_field(res, pending) do
      errors =
        Enum.map(pending, fn {item_idx, term} -> with_path(term, Enum.reverse(item_idx)) end)

      %{res | value: nil, errors: errors}
    end

    defp with_path(term, []), do: term

    defp with_path(term, path) do
      term
      |> error_map()
      |> Map.put(:path, path)
    end

    defp error_map(term) when is_binary(term), do: %{message: term}
    defp error_map(term) when is_map(term) and not is_struct(term), do: term
    defp error_map([{_, _} | _] = kw), do: Map.new(kw)
    defp error_map(term), do: %{message: to_string(term)}

    defp normalize_error!(term, _spec), do: term

    # walk/4 returns
    #   {:ok, value, attached}  value (possibly changed), item errors to attach inside it
    #   {:null, pending}        this position becomes null (it is nullable)
    #   {:bubble, pending}      this position is non-null and would be null: the parent
    #                           position becomes null
    #   :filter                 remove this list item
    #   {:fail_list, denial}    deny the whole field
    #
    # `idx` is the reversed list of list indices from the field to this position.
    # `pending` and `attached` carry {item_idx, error_term} (and the attach position).
    defp walk(nil, _shape, _ctx, _idx), do: {:ok, nil, []}

    defp walk(value, {:non_null, inner}, ctx, idx) do
      case walk(value, inner, ctx, idx) do
        {:null, pending} -> {:bubble, pending}
        other -> other
      end
    end

    defp walk(values, {:list, inner}, ctx, idx) when is_list(values) do
      walk_items(values, 0, inner, ctx, idx, [], [])
    end

    # A non-list value for a list type: Absinthe wraps it with List.wrap/1. Check it as
    # the single item it will become.
    defp walk(value, {:list, inner}, ctx, idx), do: walk([value], {:list, inner}, ctx, idx)

    # Every checked position was decided by `Warden.Absinthe.Decide` before the walk.
    defp walk({@decided, value, outcome}, :named, ctx, idx) do
      case outcome do
        :ok -> {:ok, value, []}
        {:deny, denial} -> object_denied(denial, ctx, idx)
      end
    end

    # A denied object: in a list, the list policy decides; otherwise the handler does.
    defp object_denied(denial, ctx, idx) do
      in_list? = idx != []
      policy = if in_list?, do: ctx.spec.list_policy, else: nil

      denial = %{
        denial
        | value_index: if(in_list?, do: Enum.reverse(idx), else: nil),
          list_policy: policy
      }

      if policy == :fail_list,
        do: {:fail_list, denial},
        else: denied_item(call_deny(ctx.spec.authorizer, denial), policy, idx, ctx)
    end

    defp denied_item(:null, :filter, _idx, _ctx), do: :filter
    defp denied_item(:null, _policy, _idx, _ctx), do: {:null, []}
    defp denied_item({:error, term}, _policy, idx, _ctx), do: {:null, [{idx, term}]}
    defp denied_item(other, _policy, _idx, ctx), do: object_replace_error!(ctx.spec, other)

    # `acc` and `attached` are built in reverse (prepending) so the walk stays linear in
    # the number of items.
    defp walk_items([], _i, _inner, _ctx, _idx, acc, attached),
      do: {:ok, Enum.reverse(acc), Enum.reverse(attached)}

    # `i` is the index in the OUTPUT list: filtered items do not count, so error paths
    # never point at another item or reveal the original position.
    defp walk_items([value | rest], i, inner, ctx, idx, acc, attached) do
      item_idx = [i | idx]

      case walk(value, inner, ctx, item_idx) do
        {:ok, value, a} ->
          walk_items(rest, i + 1, inner, ctx, idx, [value | acc], Enum.reverse(a, attached))

        {:null, pending} ->
          a = Enum.map(pending, fn {ii, term} -> {item_idx, ii, term} end)
          walk_items(rest, i + 1, inner, ctx, idx, [nil | acc], Enum.reverse(a, attached))

        :filter ->
          walk_items(rest, i, inner, ctx, idx, acc, attached)

        {:bubble, pending} ->
          # The item cannot be null, so this list becomes null. Errors already attached
          # to positions inside it move up with it, and the remaining items are still
          # checked so every denied item is reported.
          unattached =
            attached |> Enum.reverse() |> Enum.map(fn {_at, ii, term} -> {ii, term} end)

          collect_rest(rest, i + 1, inner, ctx, idx, Enum.reverse(unattached ++ pending))

        {:fail_list, _} = fail ->
          fail
      end
    end

    # `pending` is built in reverse here.
    defp collect_rest([], _i, _inner, _ctx, _idx, pending), do: {:null, Enum.reverse(pending)}

    defp collect_rest([value | rest], i, inner, ctx, idx, pending) do
      case walk(value, inner, ctx, [i | idx]) do
        {:ok, _value, a} ->
          more = Enum.map(a, fn {_at, ii, term} -> {ii, term} end)
          collect_rest(rest, i + 1, inner, ctx, idx, Enum.reverse(more, pending))

        {tag, more} when tag in [:null, :bubble] ->
          collect_rest(rest, i + 1, inner, ctx, idx, Enum.reverse(more, pending))

        :filter ->
          collect_rest(rest, i, inner, ctx, idx, pending)

        {:fail_list, _} = fail ->
          fail
      end
    end

    defp innermost_non_null?({:non_null, :named}), do: true
    defp innermost_non_null?({_, inner}), do: innermost_non_null?(inner)
    defp innermost_non_null?(:named), do: false

    # The same resolve-type functions Absinthe's executor uses for abstract types.
    def resolve_concrete(kind, abstract, value, res) do
      type = Absinthe.Schema.lookup_type(res.schema, abstract)

      concrete =
        case kind do
          :union -> Union.resolve_type(type, value, res)
          :interface -> Interface.resolve_type(type, value, res)
        end

      case concrete do
        %{identifier: ident} -> ident
        _ -> nil
      end
    end

    @spec object_replace_error!(map, term) :: no_return()
    defp object_replace_error!(spec, other) do
      raise Warden.PolicyError,
            "#{inspect(spec.authorizer)}.deny/1 returned #{Shape.describe(other)} for an object " <>
              "denial; expected {:error, term} or :null"
    end

    ## Item errors

    defp record_item_errors(res, attached) do
      field_path = Resolution.path(res)
      location = res.definition.source_location

      entries =
        Enum.map(attached, fn {attach_idx, item_idx, term} ->
          {message, extra} = split_error!(term, res)

          error = %Absinthe.Phase.Error{
            phase: __MODULE__,
            message: message,
            locations: [location],
            path: field_path ++ Enum.reverse(item_idx),
            extra: extra
          }

          {field_path ++ Enum.reverse(attach_idx), error}
        end)

      put_marker(res, :items, entries)
    end

    # Markers travel in `resolution.extensions`, which Absinthe copies onto this field's
    # result node (`to_result/4` in Absinthe's resolution phase). They live in the
    # document's own result tree, so documents batched by `Absinthe.Pipeline.BatchResolver`
    # (which share one accumulator) never see each other's markers. The accumulator only
    # carries a flag that asks `Warden.Absinthe.Plugin` for the phase.
    #
    # Absinthe also copies `extensions` onto every list item node and into later fields'
    # resolutions. Each marker therefore names its owner (the field's response path); the
    # phase takes a marker only from the node at that path and skips inherited copies, and
    # a field never extends a marker it inherited.
    defp put_marker(res, kind, entries) do
      owner = Resolution.path(res)

      marker =
        case Map.get(res.extensions || %{}, @acc_key) do
          %{owner: ^owner} = own -> own
          _ -> %{owner: owner, items: [], folds: []}
        end

      marker = Map.update!(marker, kind, &(entries ++ &1))
      state = res.acc |> Map.get(@acc_key, %{}) |> Map.put(:pending, true)

      %{
        res
        | extensions: Map.put(res.extensions || %{}, @acc_key, marker),
          acc: Map.put(res.acc, @acc_key, state)
      }
    end

    # Absinthe folds a null in a non-null field into its parent object, except when that
    # object sits two or more list levels deep. Record every non-null field Warden nulls
    # inside a list; `Warden.Absinthe.Phase.ItemErrors` folds the ones Absinthe left alone.
    def maybe_record_fold(%Resolution{value: nil} = res) do
      path = Resolution.path(res)

      if match?(%Absinthe.Type.NonNull{}, res.definition.schema_node.type) and
           Enum.any?(path, &is_integer/1) do
        put_marker(res, :folds, [path])
      else
        res
      end
    end

    def maybe_record_fold(res), do: res

    defp split_error!(term, _res) when is_binary(term), do: {term, %{}}

    defp split_error!(term, res) when is_list(term) or (is_map(term) and not is_struct(term)) do
      {special, extra} = term |> Enum.to_list() |> Keyword.split([:message, :path])

      case Keyword.fetch(special, :message) do
        {:ok, message} ->
          {message, Map.new(extra)}

        :error ->
          raise Warden.PolicyError,
                "a denial error must have a :message, got #{Shape.describe(term)} for " <>
                  "#{inspect(Resolution.path(res))}"
      end
    end

    defp split_error!(term, _res), do: {to_string(term), %{}}

    ## Helpers

    defp field_ident(%Resolution{definition: %{schema_node: %{identifier: ident}}}), do: ident
    defp field_ident(_), do: nil

    defp parent_ident(%Resolution{parent_type: %{identifier: ident}}), do: ident
    defp parent_ident(_), do: nil
  end
end
