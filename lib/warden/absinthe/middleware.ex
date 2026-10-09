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

    alias Absinthe.Resolution
    alias Absinthe.Type.{Interface, Union}
    alias Warden.{Actor, Check, Denial, Rule}
    alias Warden.Authorizer.Callbacks

    @acc_key Warden

    ## Specs

    def pre_spec(spec), do: {{__MODULE__, :pre}, spec}
    def post_spec(spec), do: {{__MODULE__, :post}, spec}
    def shim_spec(shim_args, post), do: {{__MODULE__, :shim}, {shim_args, post}}

    def warden_entry?({{__MODULE__, _}, _}), do: true
    def warden_entry?(_), do: false

    ## Actor

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
      walk = %{inputs: inputs, base: base, authorizer: authorizer}

      first_denial(args, fn {ident, rule, defaults, specs} ->
        check_entry(base.args, ident, {rule, defaults, specs}, [ident], walk)
      end)
    end

    # Runs `fun` on each item until one returns something other than `:ok`.
    defp first_denial(items, fun) do
      Enum.reduce_while(items, :ok, fn item, :ok ->
        case fun.(item) do
          :ok -> {:cont, :ok}
          denial -> {:halt, denial}
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
    # {rule, defaults, input_specs}.
    defp check_entry(map, key, declaration, path, walk) do
      check_input_value(Map.has_key?(map, key), Map.get(map, key), declaration, path, walk)
    end

    defp check_input_value(present?, value, {rule, defaults, specs}, path, walk) do
      with :ok <- check_input_rule(present?, value, rule, defaults, path, walk) do
        first_denial(specs, &walk_input(value, &1, path, walk))
      end
    end

    defp check_input_rule(present?, value, rule, defaults, path, walk) do
      if rule != nil and restricted?(present?, value, defaults),
        do: evaluate_input_rule(rule, path, walk),
        else: :ok
    end

    defp evaluate_input_rule(rule, path, %{base: base, authorizer: authorizer}) do
      case Rule.evaluate(rule, %{base | argument: path}, authorizer) do
        :ok -> :ok
        {:deny, failure} -> {:deny, :argument, rule, failure, [argument: path]}
      end
    end

    defp walk_input(nil, _spec, _path, _walk), do: :ok
    defp walk_input(_value, nil, _path, _walk), do: :ok

    defp walk_input(value, {:non_null, spec}, path, walk),
      do: walk_input(value, spec, path, walk)

    defp walk_input(values, {:list, spec}, path, walk) when is_list(values) do
      values
      |> Enum.with_index()
      |> first_denial(fn {value, index} -> walk_input(value, spec, path ++ [index], walk) end)
    end

    # A single value given for a list input is coerced to a list by Absinthe; walk it as
    # an item in case a custom pipeline did not.
    defp walk_input(value, {:list, spec}, path, walk),
      do: walk_input(value, spec, path ++ [0], walk)

    defp walk_input(value, {:input, ident}, path, walk) when is_map(value) do
      walk.inputs
      |> Map.fetch!(ident)
      |> first_denial(fn {field, rule, defaults, specs} ->
        check_entry(value, field, {rule, defaults, specs}, path ++ [field], walk)
      end)
    end

    defp walk_input(_value, {:input, _}, _path, _walk), do: :ok

    defp apply_pre_denial(res, %Denial{kind: kind} = denial, authorizer) do
      case call_deny(authorizer, denial) do
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

    def call_deny(authorizer, %Denial{} = denial) do
      case Callbacks.deny(authorizer, denial) do
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

      value
      |> walk(spec.shape, ctx, [])
      |> finish_post(res, spec)
    end

    def post(res, _spec), do: res

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

    defp walk(value, :named, ctx, idx) do
      case check_object(value, ctx) do
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

    defp check_object(value, %{spec: %{abstract: nil} = spec} = ctx) do
      check_rule(Map.get(spec.rules, spec.named), spec.named, value, ctx)
    end

    defp check_object(value, %{spec: spec} = ctx) do
      with :ok <- check_rule(spec.abstract_rule, spec.named, value, ctx) do
        check_concrete(value, ctx)
      end
    end

    defp check_concrete(_value, %{spec: %{rules: rules}}) when map_size(rules) == 0, do: :ok

    defp check_concrete(value, %{spec: spec} = ctx) do
      case resolve_concrete(spec.abstract, spec.named, value, ctx.res) do
        nil ->
          # Fail closed: a value whose concrete type cannot be determined cannot be
          # checked against the concrete type's rule.
          failure = %{failed_rule: :deny, missing_roles: [], missing_permissions: []}
          deny_object(:deny, failure, spec.named, ctx)

        concrete ->
          check_rule(Map.get(spec.rules, concrete), concrete, value, ctx)
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
end
