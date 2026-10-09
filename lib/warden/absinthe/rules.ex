# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Rules do
    @moduledoc false
    # Rule helpers used only by the GraphQL layer.

    @list_policies [:null_item, :filter, :fail_list]

    @spec list_policies() :: [Warden.Rule.list_policy()]
    def list_policies, do: @list_policies

    # Combines rules with AND, dropping `:public` and `nil`.
    @spec conjoin([Warden.Rule.t() | nil]) :: Warden.Rule.t() | nil
    def conjoin(rules) do
      case rules |> Enum.reject(&(&1 in [nil, :public])) |> Enum.uniq() do
        [] -> nil
        [rule] -> rule
        rules -> {:all, rules}
      end
    end
  end
end
