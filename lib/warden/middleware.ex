defmodule Warden.Middleware do
  @moduledoc false
  # The two middleware entries Warden attaches to fields.
  #
  #   * `pre/2` runs first: the parent object rule, the effective field rule and the
  #     argument / input-field rules. On denial the resolver and the rest of the chain do
  #     not run.
  #   * `post/2` runs last: the object rules of the resolved value, per list item.
  #
  # Both are attached by `Warden.Phase.Attach` at schema compile time.

  alias Absinthe.Resolution
  alias Warden.{Actor, Check, Denial, Rule}

  @acc_key Warden

  ## Specs

  @doc false
  def pre_spec(spec), do: {{__MODULE__, :pre}, spec}
  @doc false
  def post_spec(spec), do: {{__MODULE__, :post}, spec}
  @doc false
  def shim_spec(shim_args, post), do: {{__MODULE__, :shim}, {shim_args, post}}

  @doc false
  def warden_entry?({{__MODULE__, _}, _}), do: true
  def warden_entry?(_), do: false

  ## Actor

  @doc false
  # The actor is built once per document execution and cached in `resolution.acc`.
  def actor(%Resolution{acc: acc, context: context} = res, authorizer) do
    case acc do
      %{@acc_key => %{actor: %Actor{} = actor}} ->
        {actor, res}

      _ ->
        actor = Actor.build(authorizer, context)
        state = Map.get(acc, @acc_key, %{})
        {actor, %{res | acc: Map.put(acc, @acc_key, Map.put(state, :actor, actor))}}
    end
  end

  ## Pre

  @doc false
  def pre(%Resolution{} = res, %{authorizer: authorizer, checks: checks}) do
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

    case run_checks(checks, base, authorizer) do
      :ok ->
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
              actor: actor,
              path: Resolution.path(res),
              field: base.field,
              parent_type: base.parent_type
            ] ++ extra
          )

        apply_pre_denial(res, denial, authorizer)
    end
  end

  @doc false
  # Shared with subscribe-time checks. Returns :ok or
  # {:deny, kind, rule, failure, extra_denial_fields}.
  def run_checks(checks, %Check{} = base, authorizer) do
    Enum.reduce_while(checks, :ok, fn check, :ok ->
      case run_check(check, base, authorizer) do
        :ok -> {:cont, :ok}
        denial -> {:halt, denial}
      end
    end)
  end

  defp run_check({:object, type, rule}, base, authorizer) do
    case Rule.evaluate(rule, %{base | type: type}, authorizer) do
      :ok -> :ok
      {:deny, failure} -> {:deny, :object, rule, failure, [type: type]}
    end
  end

  defp run_check({:field, rule}, base, authorizer) do
    case Rule.evaluate(rule, base, authorizer) do
      :ok -> :ok
      {:deny, failure} -> {:deny, :field, rule, failure, []}
    end
  end

  defp run_check({:introspection, rule}, base, authorizer) do
    case Rule.evaluate(rule, base, authorizer) do
      :ok -> :ok
      {:deny, failure} -> {:deny, :introspection, rule, failure, []}
    end
  end

  defp run_check({:args, %{args: args, inputs: inputs}}, base, authorizer) do
    Enum.reduce_while(args, :ok, fn {ident, rule, default, spec}, :ok ->
      value = Map.get(base.args, ident)

      case check_input_value(value, rule, default, spec, [ident], inputs, base, authorizer) do
        :ok -> {:cont, :ok}
        denial -> {:halt, denial}
      end
    end)
  end

  defp check_input_value(value, rule, default, spec, path, inputs, base, authorizer) do
    rule_result =
      if rule != nil and value !== default do
        case Rule.evaluate(rule, %{base | argument: path}, authorizer) do
          :ok -> :ok
          {:deny, failure} -> {:deny, :argument, rule, failure, [argument: path]}
        end
      else
        :ok
      end

    case rule_result do
      :ok -> walk_input(value, spec, path, inputs, base, authorizer)
      denial -> denial
    end
  end

  defp walk_input(nil, _spec, _path, _inputs, _base, _authorizer), do: :ok
  defp walk_input(_value, nil, _path, _inputs, _base, _authorizer), do: :ok

  defp walk_input(value, {:non_null, spec}, path, inputs, base, authorizer),
    do: walk_input(value, spec, path, inputs, base, authorizer)

  defp walk_input(values, {:list, spec}, path, inputs, base, authorizer) when is_list(values) do
    values
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {value, index}, :ok ->
      case walk_input(value, spec, path ++ [index], inputs, base, authorizer) do
        :ok -> {:cont, :ok}
        denial -> {:halt, denial}
      end
    end)
  end

  # A single value given for a list input is coerced to a list by Absinthe; walk it as
  # an item in case a custom pipeline did not.
  defp walk_input(value, {:list, spec}, path, inputs, base, authorizer),
    do: walk_input(value, spec, path ++ [0], inputs, base, authorizer)

  defp walk_input(value, {:input, ident}, path, inputs, base, authorizer) when is_map(value) do
    inputs
    |> Map.fetch!(ident)
    |> Enum.reduce_while(:ok, fn {field, rule, default, spec}, :ok ->
      field_value = Map.get(value, field)

      case check_input_value(
             field_value,
             rule,
             default,
             spec,
             path ++ [field],
             inputs,
             base,
             authorizer
           ) do
        :ok -> {:cont, :ok}
        denial -> {:halt, denial}
      end
    end)
  end

  defp walk_input(_value, {:input, _}, _path, _inputs, _base, _authorizer), do: :ok

  defp apply_pre_denial(res, %Denial{kind: kind} = denial, authorizer) do
    case call_deny(authorizer, denial) do
      {:error, term} ->
        res
        |> Resolution.put_result({:error, term})
        |> Map.put(:middleware, [])

      :null ->
        %{res | state: :resolved, value: nil, middleware: []}

      {:replace, value} when kind == :field ->
        # Object rules still apply to the replacement value.
        %{res | state: :resolved, value: value, middleware: post_only(res.middleware)}

      other ->
        raise Warden.PolicyError,
              "#{inspect(authorizer)}.deny/1 returned #{inspect(other)} for a #{inspect(kind)} " <>
                "denial; expected {:error, term} or :null" <>
                if(kind == :field, do: " or {:replace, value}", else: "")
    end
  end

  defp post_only(middleware) do
    Enum.flat_map(middleware, fn
      {{__MODULE__, :post}, _} = post -> [post]
      {{__MODULE__, :shim}, {_, post}} -> [post_spec(post)]
      _ -> []
    end)
  end

  @doc false
  def call_deny(authorizer, %Denial{} = denial) do
    case authorizer.deny(denial) do
      {:error, _} = result ->
        result

      :null ->
        :null

      {:replace, _} = result ->
        result

      other ->
        raise Warden.PolicyError, "#{inspect(authorizer)}.deny/1 returned #{inspect(other)}"
    end
  end

  ## Shim

  @doc false
  # Absinthe could not escape this field's middleware at compile time, so its shim
  # expands it at runtime and replaces the rest of the chain. Run it, then put Warden's
  # post middleware back at the end.
  def shim(%Resolution{} = res, {shim_args, post}) do
    res = Absinthe.Middleware.shim(res, shim_args)
    %{res | middleware: res.middleware ++ [post_spec(post)]}
  end

  ## Post

  @doc false
  # Middleware appended to the chain at runtime (after this entry was placed) would run
  # after the check and could change the value. Move the check behind it.
  def post(%Resolution{middleware: [_ | _] = rest} = res, spec) do
    %{res | middleware: rest ++ [post_spec(spec)]}
  end

  def post(%Resolution{state: :resolved, errors: [], value: value} = res, spec) do
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

    case walk(value, spec.shape, ctx, []) do
      {:ok, value, []} ->
        %{res | value: value}

      {:ok, value, attached} ->
        if innermost_non_null?(spec.shape) do
          # Absinthe's null propagation nulls the whole list field when a null appears
          # at any depth of a list whose innermost item type is non-null
          # (`null_allowed_in_list?/1` only looks at the innermost type). Report the
          # errors on the field so they are not lost.
          null_field(res, Enum.map(attached, fn {_at, ii, term} -> {ii, term} end))
        else
          res = %{res | value: value}
          record_item_errors(res, attached)
        end

      {tag, pending} when tag in [:null, :bubble] ->
        null_field(res, pending)

      :filter ->
        # Only produced inside lists; unreachable at the top level.
        %{res | value: nil}

      {:fail_list, denial} ->
        case call_deny(spec.authorizer, denial) do
          {:error, term} -> %{res | value: nil, errors: [normalize_error!(term, spec)]}
          :null -> %{res | value: nil}
          other -> object_replace_error!(spec, other)
        end
    end
  end

  def post(res, _spec), do: res

  defp null_field(res, pending) do
    errors = Enum.map(pending, fn {item_idx, term} -> with_path(term, Enum.reverse(item_idx)) end)
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

  defp walk(value, :named, ctx, idx) do
    case check_object(value, ctx) do
      :ok ->
        {:ok, value, []}

      {:deny, denial} ->
        in_list? = idx != []
        policy = if in_list?, do: ctx.spec.list_policy, else: nil

        denial = %{
          denial
          | value_index: if(in_list?, do: Enum.reverse(idx), else: nil),
            list_policy: policy
        }

        cond do
          policy == :fail_list ->
            {:fail_list, denial}

          true ->
            case call_deny(ctx.spec.authorizer, denial) do
              :null when policy == :filter -> :filter
              :null -> {:null, []}
              {:error, term} -> {:null, [{idx, term}]}
              other -> object_replace_error!(ctx.spec, other)
            end
        end
    end
  end

  defp walk_items([], _i, _inner, _ctx, _idx, acc, attached),
    do: {:ok, Enum.reverse(acc), attached}

  defp walk_items([value | rest], i, inner, ctx, idx, acc, attached) do
    item_idx = [i | idx]

    case walk(value, inner, ctx, item_idx) do
      {:ok, value, a} ->
        walk_items(rest, i + 1, inner, ctx, idx, [value | acc], attached ++ a)

      {:null, pending} ->
        a = Enum.map(pending, fn {ii, term} -> {item_idx, ii, term} end)
        walk_items(rest, i + 1, inner, ctx, idx, [nil | acc], attached ++ a)

      :filter ->
        walk_items(rest, i + 1, inner, ctx, idx, acc, attached)

      {:bubble, pending} ->
        # The item cannot be null, so this list becomes null. Errors already attached
        # to positions inside it move up with it, and the remaining items are still
        # checked so every denied item is reported.
        unattached = Enum.map(attached, fn {_at, ii, term} -> {ii, term} end)
        collect_rest(rest, i + 1, inner, ctx, idx, unattached ++ pending)

      {:fail_list, _} = fail ->
        fail
    end
  end

  defp collect_rest([], _i, _inner, _ctx, _idx, pending), do: {:null, pending}

  defp collect_rest([value | rest], i, inner, ctx, idx, pending) do
    case walk(value, inner, ctx, [i | idx]) do
      {:ok, _value, a} ->
        more = Enum.map(a, fn {_at, ii, term} -> {ii, term} end)
        collect_rest(rest, i + 1, inner, ctx, idx, pending ++ more)

      {tag, more} when tag in [:null, :bubble] ->
        collect_rest(rest, i + 1, inner, ctx, idx, pending ++ more)

      :filter ->
        collect_rest(rest, i + 1, inner, ctx, idx, pending)

      {:fail_list, _} = fail ->
        fail
    end
  end

  defp innermost_non_null?({:non_null, :named}), do: true
  defp innermost_non_null?({_, inner}), do: innermost_non_null?(inner)
  defp innermost_non_null?(:named), do: false

  defp check_object(value, %{spec: spec} = ctx) do
    case spec.abstract do
      nil ->
        check_rule(Map.get(spec.rules, spec.named), spec.named, value, ctx)

      kind ->
        with :ok <- check_rule(spec.abstract_rule, spec.named, value, ctx) do
          if map_size(spec.rules) == 0 do
            :ok
          else
            case resolve_concrete(kind, spec.named, value, ctx.res) do
              nil ->
                # Fail closed: a value whose concrete type cannot be determined cannot
                # be checked against the concrete type's rule.
                deny_object(
                  :deny,
                  %{failed_rule: :deny, missing_roles: [], missing_permissions: []},
                  spec.named,
                  ctx
                )

              concrete ->
                check_rule(Map.get(spec.rules, concrete), concrete, value, ctx)
            end
          end
        end
    end
  end

  defp check_rule(nil, _type, _value, _ctx), do: :ok

  defp check_rule(rule, type, value, ctx) do
    case Rule.evaluate(rule, %{ctx.base | value: value, type: type}, ctx.spec.authorizer) do
      :ok -> :ok
      {:deny, failure} -> deny_object(rule, failure, type, ctx)
    end
  end

  defp deny_object(rule, failure, type, ctx) do
    {:deny,
     %Denial{
       kind: :object,
       rule: rule,
       failed_rule: failure.failed_rule,
       missing_roles: failure.missing_roles,
       missing_permissions: failure.missing_permissions,
       actor: ctx.actor,
       path: Resolution.path(ctx.res),
       field: ctx.base.field,
       parent_type: ctx.base.parent_type,
       type: type
     }}
  end

  @doc false
  # The same resolve-type functions Absinthe's executor uses for abstract types.
  def resolve_concrete(kind, abstract, value, res) do
    type = Absinthe.Schema.lookup_type(res.schema, abstract)

    concrete =
      case kind do
        :union -> Absinthe.Type.Union.resolve_type(type, value, res)
        :interface -> Absinthe.Type.Interface.resolve_type(type, value, res)
      end

    case concrete do
      %{identifier: ident} -> ident
      _ -> nil
    end
  end

  defp object_replace_error!(spec, other) do
    raise Warden.PolicyError,
          "#{inspect(spec.authorizer)}.deny/1 returned #{inspect(other)} for an object " <>
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

    state = Map.get(res.acc, @acc_key, %{})
    state = Map.update(state, :item_errors, entries, &(&1 ++ entries))
    %{res | acc: Map.put(res.acc, @acc_key, state)}
  end

  defp split_error!(term, _res) when is_binary(term), do: {term, %{}}

  defp split_error!(term, res) when is_list(term) or (is_map(term) and not is_struct(term)) do
    {special, extra} = term |> Enum.to_list() |> Keyword.split([:message, :path])

    case Keyword.fetch(special, :message) do
      {:ok, message} ->
        {message, Map.new(extra)}

      :error ->
        raise Warden.PolicyError,
              "a denial error must have a :message, got #{inspect(term)} for " <>
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
