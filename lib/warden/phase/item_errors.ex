defmodule Warden.Phase.ItemErrors do
  @moduledoc false
  # Runs once, after the last resolution pass (see `Warden.Plugin`), and then drains the
  # Warden entries from the accumulator, so it can never cause another pass.
  #
  #   * Item errors: attaches recorded list-item denial errors to their (null) result
  #     nodes. Absinthe cannot carry them itself (see `Warden.Plugin`).
  #   * Folds: a non-null field Warden nulled inside an object that sits two or more list
  #     levels deep is not folded by Absinthe's null propagation. Warden folds it here:
  #     the object becomes null, and further up while the positions are non-null.
  #
  # The entries are markers in the result nodes' `extensions` (see
  # `Warden.Middleware.put_marker/3`), so each document only ever applies its own, also
  # when `Absinthe.Pipeline.BatchResolver` runs several documents with one shared
  # accumulator. The phase clears the accumulator flag and strips the markers.

  use Absinthe.Phase

  alias Absinthe.Blueprint.Result
  alias Absinthe.Type

  @impl Absinthe.Phase
  def run(%{execution: %{acc: acc, result: result} = exec} = blueprint, _opts) do
    case acc do
      %{Warden => state} ->
        {result, markers} = strip(result, [])
        items = markers |> Enum.flat_map(& &1.items) |> Enum.uniq()
        folds = markers |> Enum.flat_map(& &1.folds) |> Enum.uniq()

        result =
          Enum.reduce(items, result, fn {path, error}, tree ->
            case attach(tree, path, error) do
              {:ok, tree} -> tree
              :error -> tree
            end
          end)

        result = Enum.reduce(folds, result, &fold(&2, &1))

        acc = Map.put(acc, Warden, Map.put(state, :pending, false))
        {:ok, %{blueprint | execution: %{exec | result: result, acc: acc}}}

      _ ->
        {:ok, blueprint}
    end
  end

  # Removes Warden markers from every node's extensions and collects them.
  defp strip(%{extensions: %{Warden => marker} = ext} = node, acc) do
    strip(%{node | extensions: Map.delete(ext, Warden)}, [marker | acc])
  end

  defp strip(%Result.Object{fields: fields} = node, acc) when is_list(fields) do
    {fields, acc} = Enum.map_reduce(fields, acc, &strip/2)
    {%{node | fields: fields}, acc}
  end

  defp strip(%Result.List{values: values} = node, acc) when is_list(values) do
    {values, acc} = Enum.map_reduce(values, acc, &strip/2)
    {%{node | values: values}, acc}
  end

  defp strip(node, acc), do: {node, acc}

  ## Item errors

  # Only a null leaf takes the error: attaching an error to any other node would null
  # a value that Warden did not deny.
  defp attach(%Result.Leaf{value: nil, errors: errors} = leaf, [], error) do
    {:ok, %{leaf | errors: errors ++ [error]}}
  end

  defp attach(_node, [], _error), do: :error

  defp attach(%Result.Object{fields: fields} = node, [key | rest], error)
       when is_binary(key) and is_list(fields) do
    case Enum.find_index(fields, &(response_key(&1) == key)) do
      nil ->
        :error

      index ->
        with {:ok, child} <- attach(Enum.at(fields, index), rest, error) do
          {:ok, %{node | fields: List.replace_at(fields, index, child)}}
        end
    end
  end

  defp attach(%Result.List{values: values} = node, [index | rest], error)
       when is_integer(index) and is_list(values) do
    case Enum.at(values, index) do
      nil ->
        :error

      child ->
        with {:ok, child} <- attach(child, rest, error) do
          {:ok, %{node | values: List.replace_at(values, index, child)}}
        end
    end
  end

  defp attach(_node, _path, _error), do: :error

  ## Folds

  defp fold(root, path) do
    case descend(root, path, nil) do
      {:ok, tree} -> tree
      # The null reached the operation: the whole data becomes null.
      {:bubble, errors} -> %Result.Leaf{emitter: root.emitter, value: nil, errors: errors}
      :skip -> root
    end
  end

  # The nulled field itself: a null leaf in a non-null position.
  defp descend(%Result.Leaf{value: nil} = leaf, [], slot) do
    if non_null?(slot), do: {:bubble, collect_errors(leaf)}, else: :skip
  end

  defp descend(_node, [], _slot), do: :skip

  defp descend(%Result.Object{fields: fields} = node, [key | rest], slot)
       when is_binary(key) and is_list(fields) do
    case Enum.find_index(fields, &(response_key(&1) == key)) do
      nil ->
        :skip

      index ->
        child = Enum.at(fields, index)

        case descend(child, rest, child.emitter.schema_node.type) do
          {:ok, child} ->
            {:ok, %{node | fields: List.replace_at(fields, index, child)}}

          {:bubble, errors} ->
            others = fields |> List.delete_at(index) |> Enum.flat_map(&collect_errors/1)
            null_here(node, slot, node.errors ++ errors ++ others)

          :skip ->
            :skip
        end
    end
  end

  defp descend(%Result.List{values: values} = node, [index | rest], slot)
       when is_integer(index) and is_list(values) do
    case Enum.at(values, index) do
      nil ->
        :skip

      child ->
        case descend(child, rest, item_type(slot)) do
          {:ok, child} ->
            {:ok, %{node | values: List.replace_at(values, index, child)}}

          {:bubble, errors} ->
            others = values |> List.delete_at(index) |> Enum.flat_map(&collect_errors/1)
            null_here(node, slot, node.errors ++ errors ++ others)

          :skip ->
            :skip
        end
    end
  end

  defp descend(_node, _path, _slot), do: :skip

  defp null_here(node, slot, errors) do
    if non_null?(slot) do
      {:bubble, errors}
    else
      {:ok,
       %Result.Leaf{
         emitter: node.emitter,
         value: nil,
         errors: errors,
         extensions: node.extensions
       }}
    end
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
