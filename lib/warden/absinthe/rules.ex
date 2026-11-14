# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Rules do
    @moduledoc false
    # Rule helpers used only by the GraphQL layer.

    @list_policies [:null_item, :filter, :fail_list]

    @spec list_policies() :: [Warden.Rule.list_policy()]
    def list_policies, do: @list_policies

    @spec valid_on_deny?(term) :: boolean
    def valid_on_deny?(on_deny) when on_deny in [:null, :error], do: true
    def valid_on_deny?({:replace, _value}), do: true
    def valid_on_deny?(_on_deny), do: false

    # Combines rules with AND, dropping `nil`, `:public` and `:covered` (which always
    # passes; the verifier checks that an object rule guards it).
    @spec conjoin([Warden.Rule.t() | nil]) :: Warden.Rule.t() | nil
    def conjoin(rules) do
      case rules |> Enum.reject(&(&1 in [nil, :public, :covered])) |> Enum.uniq() do
        [] -> nil
        [rule] -> rule
        rules -> {:all, rules}
      end
    end
  end
end
