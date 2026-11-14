defmodule Warden.Fields.Redactor do
  @moduledoc false
  # Applies field policies. Any module that exports `__warden_fields__(:info)`, returning
  # `%{authorizer: module, for: module, struct_fields: [atom],
  # redactions: [%{field: atom, with: term, rule: rule}]}`, is a field policy;
  # `use Warden.Fields` generates it.
  #
  # Every rule of a field policy is decided for a whole group of structs with one
  # `Warden.Evaluator.many/3` call, so a batched check runs once per rule and group. The
  # actor (with the tenant roles it read) is threaded through and returned.

  alias Warden.{Actor, Check, Evaluator, Telemetry}

  @deep_option :deep

  @spec info!(term) :: map
  def info!(fields_module) when is_atom(fields_module) do
    if Code.ensure_loaded?(fields_module) and
         function_exported?(fields_module, :__warden_fields__, 1) do
      fields_module.__warden_fields__(:info)
    else
      raise Warden.PolicyError,
            "#{inspect(fields_module)} is not a Warden field policy (use Warden.Fields)"
    end
  end

  def info!(other),
    do: raise(Warden.PolicyError, "not a Warden field policy: #{inspect(other)}")

  # `%{struct_module => fields_module}` for every field policy the authorizer lists. Two
  # field policies for one struct are refused: which one applies would depend on list
  # order.
  @spec registry(module) :: %{module => module}
  def registry(authorizer) do
    authorizer.__warden_catalog__()
    |> Map.get(:fields, [])
    |> Enum.reduce(%{}, fn fields_module, registry ->
      struct_module = info!(fields_module).for

      case Map.fetch(registry, struct_module) do
        {:ok, other} -> duplicate!(authorizer, struct_module, other, fields_module)
        :error -> Map.put(registry, struct_module, fields_module)
      end
    end)
  end

  @spec duplicate!(module, module, module, module) :: no_return()
  defp duplicate!(authorizer, struct_module, first, second) do
    raise Warden.PolicyError, """
    #{inspect(authorizer)} lists two field policies for #{inspect(struct_module)}: \
    #{inspect(first)} and #{inspect(second)}; declare every field of a struct in one\
    """
  end

  # Redacts `value` for the actor: a registered struct, or the registered structs of a
  # list (order kept). With `deep?`, every registered struct inside maps, lists, tuples
  # and registered structs too; unregistered structs are left alone, contents included.
  # Returns {value, actor}.
  @spec redact(term, Actor.t(), map, module, keyword) :: {term, Actor.t()}
  def redact(value, %Actor{} = actor, context, authorizer, opts) do
    registry = registry(authorizer)
    state = %{actor: actor, context: context, authorizer: authorizer, registry: registry}

    {[redacted], state} =
      if Keyword.get(opts, @deep_option, false),
        do: deep([value], state),
        else: shallow(value, state)

    {redacted, state.actor}
  end

  # The fields of `struct` the actor may not read, and the updated actor. A struct
  # without a field policy hides nothing.
  @spec hidden_fields(struct, Actor.t(), map, module) :: {[atom], Actor.t()}
  def hidden_fields(%module{} = struct, %Actor{} = actor, context, authorizer) do
    case Map.fetch(registry(authorizer), module) do
      {:ok, fields_module} ->
        {_redacted, [hidden], actor} =
          decide(fields_module, [struct], actor, context, authorizer)

        {hidden, actor}

      :error ->
        {[], actor}
    end
  end

  # Redacts structs of one field policy (the GraphQL object phase). Returns
  # {redacted, actor}.
  @spec redact_group(module, [term], Actor.t(), map, module) :: {[term], Actor.t()}
  def redact_group(_fields_module, [], actor, _context, _authorizer), do: {[], actor}

  def redact_group(fields_module, values, actor, context, authorizer) do
    {redacted, _hidden, actor} = decide(fields_module, values, actor, context, authorizer)
    {redacted, actor}
  end

  defp shallow(%module{} = struct, state) do
    if Map.has_key?(state.registry, module),
      do: redact_frontier([struct], state),
      else: {[struct], state}
  end

  defp shallow(values, state) when is_list(values) do
    frontier = for %module{} = struct <- values, Map.has_key?(state.registry, module), do: struct
    {redacted, state} = redact_frontier(frontier, state)
    {list, []} = Enum.map_reduce(values, redacted, &replace_item(&1, &2, state.registry))
    {[list], state}
  end

  defp shallow(value, state), do: {[value], state}

  defp replace_item(%module{}, [redacted | rest], registry) when is_map_key(registry, module),
    do: {redacted, rest}

  defp replace_item(value, redacted, _registry), do: {value, redacted}

  # One level of registered structs at a time: the outermost registered structs of every
  # term are redacted together (one batch per rule and policy), then their fields are
  # walked as the next level. A field the outer policy replaced is not walked into.
  defp deep(terms, state) do
    frontier = terms |> Enum.reduce([], &collect(&1, state.registry, &2)) |> Enum.reverse()

    if frontier == [] do
      {terms, state}
    else
      {redacted, state} = redact_frontier(frontier, state)
      {children, state} = redacted |> Enum.map(&Map.from_struct/1) |> deep(state)
      rebuilt = Enum.zip_with(redacted, children, &Map.merge/2)
      {terms, []} = Enum.map_reduce(terms, rebuilt, &replace(&1, &2, state.registry))
      {terms, state}
    end
  end

  # The outermost registered structs of a term, prepended to `acc` in walk order.
  defp collect(%module{} = struct, registry, acc) when is_map_key(registry, module),
    do: [struct | acc]

  defp collect(%_module{}, _registry, acc), do: acc

  defp collect(map, registry, acc) when is_map(map),
    do:
      map
      |> :maps.to_list()
      |> Enum.reduce(acc, fn {_key, value}, acc -> collect(value, registry, acc) end)

  defp collect([head | tail], registry, acc),
    do: collect(tail, registry, collect(head, registry, acc))

  defp collect(tuple, registry, acc) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> collect(registry, acc)

  defp collect(_value, _registry, acc), do: acc

  # Puts the redacted structs back in the walk order of `collect/3`. Returns
  # {term, remaining}.
  defp replace(term, [], _registry), do: {term, []}

  defp replace(%module{}, [redacted | rest], registry) when is_map_key(registry, module),
    do: {redacted, rest}

  defp replace(%_module{} = struct, redacted, _registry), do: {struct, redacted}

  defp replace(map, redacted, registry) when is_map(map) do
    {pairs, rest} =
      map
      |> :maps.to_list()
      |> Enum.map_reduce(redacted, fn {key, value}, redacted ->
        {value, redacted} = replace(value, redacted, registry)
        {{key, value}, redacted}
      end)

    {Map.new(pairs), rest}
  end

  defp replace([head | tail], redacted, registry) do
    {head, redacted} = replace(head, redacted, registry)
    {tail, redacted} = replace(tail, redacted, registry)
    {[head | tail], redacted}
  end

  defp replace(tuple, redacted, registry) when is_tuple(tuple) do
    {items, rest} = tuple |> Tuple.to_list() |> replace(redacted, registry)
    {List.to_tuple(items), rest}
  end

  defp replace(value, redacted, _registry), do: {value, redacted}

  # Redacts registered structs of any policies, in order: one decision per policy.
  defp redact_frontier([], state), do: {[], state}

  defp redact_frontier(structs, state) do
    indexed = Enum.with_index(structs)
    groups = Enum.group_by(indexed, fn {%module{}, _index} -> module end)

    {placed, actor} =
      Enum.reduce(groups, {%{}, state.actor}, fn {module, members}, {placed, actor} ->
        {indexes, values} =
          members |> Enum.map(fn {value, index} -> {index, value} end) |> Enum.unzip()

        fields_module = Map.fetch!(state.registry, module)

        {redacted, _hidden, actor} =
          decide(fields_module, values, actor, state.context, state.authorizer)

        placed = indexes |> Enum.zip(redacted) |> Map.new() |> Map.merge(placed)
        {placed, actor}
      end)

    ordered = Enum.map(0..(length(structs) - 1)//1, &Map.fetch!(placed, &1))
    {ordered, %{state | actor: actor}}
  end

  # Decides every rule of the policy for all values. Returns {redacted, hidden_fields,
  # actor}, with one entry per value.
  defp decide(fields_module, values, actor, context, authorizer) do
    info = info!(fields_module)
    ensure_usable!(fields_module, info, values, authorizer)
    rules = info.redactions |> Enum.map(& &1.rule) |> Enum.uniq()

    {verdicts, actor} =
      Enum.reduce(rules, {%{}, actor}, fn rule, {verdicts, actor} ->
        checks = Enum.map(values, &%Check{actor: actor, value: &1, context: context})
        {results, evaluated} = Evaluator.many(rule, checks, authorizer)
        emit(rule, evaluated, results)
        passed = results |> Enum.map(&(&1 == :ok)) |> List.to_tuple()
        {Map.put(verdicts, rule, passed), evaluated}
      end)

    {redacted, hidden} =
      values
      |> Enum.with_index()
      |> Enum.map(fn {value, index} ->
        apply_redactions(value, index, info.redactions, verdicts)
      end)
      |> Enum.unzip()

    {redacted, hidden, actor}
  end

  defp apply_redactions(value, index, redactions, verdicts) do
    denied =
      for redaction <- redactions,
          not elem(Map.fetch!(verdicts, redaction.rule), index),
          do: redaction

    redacted = Enum.reduce(denied, value, &Map.put(&2, &1.field, &1.with))
    hidden = Enum.map(denied, & &1.field)
    {redacted, hidden}
  end

  # The error names the policy and the struct module, never the value.
  defp ensure_usable!(fields_module, info, values, authorizer) do
    cond do
      info.authorizer != authorizer ->
        raise Warden.PolicyError, """
        #{inspect(fields_module)} belongs to #{inspect(info.authorizer)}, but redaction \
        runs with #{inspect(authorizer)}\
        """

      not Enum.all?(values, &is_struct(&1, info.for)) ->
        raise Warden.PolicyError, """
        #{inspect(fields_module)} redacts #{inspect(info.for)} structs, and was given a \
        value of another type\
        """

      true ->
        :ok
    end
  end

  # One event per rule and group; the metadata never holds a value.
  defp emit(rule, actor, results) do
    denied = Enum.reject(results, &(&1 == :ok))

    decision = %{
      layer: :fields,
      kind: :field,
      rule: rule,
      actor: actor,
      count: length(results),
      denied: length(denied),
      reason: first_reason(denied)
    }

    Telemetry.decision(decision)
  end

  defp first_reason([{:deny, %{reason: reason}} | _rest]), do: reason
  defp first_reason([]), do: nil
end
