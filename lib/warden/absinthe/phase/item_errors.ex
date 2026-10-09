# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Phase.ItemErrors do
    @moduledoc false
    # Runs once, after the last resolution pass (see `Warden.Absinthe.Plugin`), and then drains the
    # Warden entries from the accumulator, so it can never cause another pass.
    #
    #   * Item errors: attaches recorded list-item denial errors to their (null) result
    #     nodes. Absinthe cannot carry them itself (see `Warden.Absinthe.Plugin`).
    #   * Folds: a non-null field Warden nulled inside an object that sits two or more list
    #     levels deep is not folded by Absinthe's null propagation. Warden folds it here:
    #     the object becomes null, and further up while the positions are non-null.
    #
    # The entries are markers in the result nodes' `extensions` (see
    # `Warden.Absinthe.Middleware.put_marker/3`), so each document only ever applies its own, also
    # when `Absinthe.Pipeline.BatchResolver` runs several documents with one shared
    # accumulator. The phase clears the accumulator flag and strips the markers.
    #
    # Cost is linear in the size of the result tree: one pass strips the markers (taking
    # each only from the node that owns it, never from inherited copies), and one pass
    # walks a trie of the recorded paths, attaching errors and folding as it returns.

    use Absinthe.Phase

    alias Absinthe.Blueprint.Result
    alias Absinthe.Type

    @impl Absinthe.Phase
    def run(%{execution: %{acc: acc, result: result} = exec} = blueprint, _opts) do
      case acc do
        %{Warden => state} ->
          {result, markers} = strip(result, [], [])

          trie =
            Enum.reduce(markers, %{}, &add_marker/2)

          result =
            case process(result, trie, nil) do
              {:ok, node} -> node
              {:bubble, node} -> node
            end

          acc = Map.put(acc, Warden, Map.put(state, :pending, false))
          {:ok, %{blueprint | execution: %{exec | result: result, acc: acc}}}

        _ ->
          {:ok, blueprint}
      end
    end

    ## Collecting markers

    # Removes Warden markers from every node's extensions. Keeps a marker only when the
    # node is its owner: Absinthe copies a field's extensions onto its list items and into
    # later resolutions, and those copies must neither be applied nor counted.
    defp strip(%{extensions: %{Warden => marker} = ext} = node, path, acc) do
      acc = if marker.owner == path, do: [marker | acc], else: acc
      strip(%{node | extensions: Map.delete(ext, Warden)}, path, acc)
    end

    defp strip(%Result.Object{fields: fields} = node, path, acc) when is_list(fields) do
      {fields, acc} = Enum.map_reduce(fields, acc, &strip(&1, path ++ [response_key(&1)], &2))
      {%{node | fields: fields}, acc}
    end

    defp strip(%Result.List{values: values} = node, path, acc) when is_list(values) do
      {values, acc} =
        values
        |> Enum.with_index()
        |> Enum.map_reduce(acc, fn {value, index}, acc -> strip(value, path ++ [index], acc) end)

      {%{node | values: values}, acc}
    end

    defp strip(node, _path, acc), do: {node, acc}

    defp add_marker(marker, trie) do
      trie = Enum.reduce(marker.items, trie, &add_item_error/2)
      Enum.reduce(marker.folds, trie, &add_fold/2)
    end

    defp add_item_error({path, error}, trie) do
      trie_put(trie, path, &Map.update(&1, :errors, [error], fn errors -> [error | errors] end))
    end

    defp add_fold(path, trie), do: trie_put(trie, path, &Map.put(&1, :fold, true))

    defp trie_put(trie, [], fun), do: fun.(trie)

    defp trie_put(trie, [key | rest], fun) do
      children = Map.get(trie, :children, %{})
      child = trie_put(Map.get(children, key, %{}), rest, fun)
      Map.put(trie, :children, Map.put(children, key, child))
    end

    ## Applying

    # Returns {:ok, node}, or {:bubble, null_leaf} when this position is non-null and
    # had to become null (the parent then becomes null too).
    defp process(node, trie, slot) do
      {node, child_bubbled?} = process_children(node, Map.get(trie, :children, %{}), slot)

      node =
        case {node, Map.get(trie, :errors)} do
          {%Result.Leaf{value: nil} = leaf, [_ | _] = errors} ->
            %{leaf | errors: leaf.errors ++ Enum.reverse(errors)}

          {node, _} ->
            node
        end

      cond do
        child_bubbled? ->
          null_here(node, slot, collect_errors(node))

        Map.get(trie, :fold) && match?(%Result.Leaf{value: nil}, node) && non_null?(slot) ->
          {:bubble, node}

        true ->
          {:ok, node}
      end
    end

    defp process_children(node, children, _slot) when map_size(children) == 0, do: {node, false}

    defp process_children(%Result.Object{fields: fields} = node, children, _slot)
         when is_list(fields) do
      {fields, bubbled?} =
        Enum.map_reduce(fields, false, fn field, bubbled? ->
          children
          |> Map.fetch(response_key(field))
          |> process_child(field, field_slot(field), bubbled?)
        end)

      {%{node | fields: fields}, bubbled?}
    end

    defp process_children(%Result.List{values: values} = node, children, slot)
         when is_list(values) do
      item_slot = item_type(slot)

      {values, {_, bubbled?}} =
        Enum.map_reduce(values, {0, false}, fn value, {index, bubbled?} ->
          {value, bubbled?} =
            children
            |> Map.fetch(index)
            |> process_child(value, item_slot, bubbled?)

          {value, {index + 1, bubbled?}}
        end)

      {%{node | values: values}, bubbled?}
    end

    defp process_children(node, _children, _slot), do: {node, false}

    # Processes one child that has recorded entries (`{:ok, trie}`) and reports whether
    # it bubbled a null up; children without entries are left as they are.
    defp process_child(:error, node, _slot, bubbled?), do: {node, bubbled?}

    defp process_child({:ok, trie}, node, slot, bubbled?) do
      case process(node, trie, slot) do
        {:ok, node} -> {node, bubbled?}
        {:bubble, node} -> {node, true}
      end
    end

    defp field_slot(field), do: field.emitter.schema_node.type

    defp null_here(node, slot, errors) do
      leaf = %Result.Leaf{
        emitter: node.emitter,
        value: nil,
        errors: errors,
        extensions: node.extensions
      }

      if non_null?(slot), do: {:bubble, leaf}, else: {:ok, leaf}
    end

    defp non_null?(%Type.NonNull{}), do: true
    defp non_null?(_), do: false

    defp item_type(%Type.NonNull{of_type: t}), do: item_type(t)
    defp item_type(%Type.List{of_type: t}), do: t
    defp item_type(_), do: nil

    defp collect_errors(%{errors: errors} = node) do
      children =
        case node do
          %Result.Object{fields: fields} when is_list(fields) -> fields
          %Result.List{values: values} when is_list(values) -> values
          _ -> []
        end

      errors ++ Enum.flat_map(children, &collect_errors/1)
    end

    defp collect_errors(_), do: []

    defp response_key(%{emitter: %{alias: nil, name: name}}), do: name
    defp response_key(%{emitter: %{alias: alias}}) when is_binary(alias), do: alias
    defp response_key(%{emitter: %{name: name}}), do: name
    defp response_key(_), do: nil
  end
end
