defmodule Warden.Phase.ItemErrors do
  @moduledoc false
  # Attaches recorded list-item denial errors to their (null) result nodes. See
  # `Warden.Plugin`. Entries whose node is not in the result tree yet (for example a
  # field that is still suspended) stay in the accumulator for the next pass.

  use Absinthe.Phase

  alias Absinthe.Blueprint.Result

  @impl Absinthe.Phase
  def run(%{execution: %{acc: acc, result: result} = exec} = blueprint, _opts) do
    case acc do
      %{Warden => %{item_errors: [_ | _] = entries} = state} ->
        {result, remaining} =
          Enum.reduce(entries, {result, []}, fn {path, error} = entry, {tree, remaining} ->
            case attach(tree, path, error) do
              {:ok, tree} -> {tree, remaining}
              :error -> {tree, [entry | remaining]}
            end
          end)

        acc = Map.put(acc, Warden, %{state | item_errors: Enum.reverse(remaining)})
        {:ok, %{blueprint | execution: %{exec | result: result, acc: acc}}}

      _ ->
        {:ok, blueprint}
    end
  end

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

  defp response_key(%{emitter: %{alias: nil, name: name}}), do: name
  defp response_key(%{emitter: %{alias: alias}}) when is_binary(alias), do: alias
  defp response_key(%{emitter: %{name: name}}), do: name
  defp response_key(_), do: nil
end
