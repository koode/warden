# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Hydrate do
    @moduledoc """
    Declares Warden rules for SDL schemas through `hydrate/2`.

        def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :email}, [%{identifier: :user} | _]) do
          [Warden.Absinthe.Hydrate.meta(rule: Warden.Rule.role(:admin))]
        end

    Absinthe's `{:meta, keyword}` hydration replaces the node's whole `meta`, so pass any
    other meta you need as the second argument:

        Warden.Absinthe.Hydrate.meta([rule: role(:admin)], cache: false)

    Rules declared this way are validated at compile time like `authorize/1` rules.
    """

    alias Warden.Rule
    alias Warden.Absinthe.Rules

    @doc """
    Builds a `{:meta, keyword}` hydration.

    Options:

      * `:rule` - a field, input-field or object rule (depending on the node).
      * `:args` - `%{arg => rule}` or a keyword list, for object fields.
      * `:list_policy` - `:null_item`, `:filter` or `:fail_list`, for object fields.
    """
    @spec meta(keyword, keyword) :: {:meta, keyword}
    def meta(opts, extra_meta \\ []) do
      entries =
        Enum.map(opts, fn
          {:rule, rule} ->
            validate!(rule, :rule)
            {:warden_rule, rule}

          {:args, args} ->
            args = Map.new(args)
            Enum.each(args, fn {_arg, rule} -> validate!(rule, :args) end)
            {:warden_args, args}

          {:list_policy, policy} ->
            unless policy in Rules.list_policies() do
              raise ArgumentError, "invalid list policy: #{inspect(policy)}"
            end

            {:warden_list_policy, policy}

          {key, _} ->
            raise ArgumentError, "unknown Warden.Absinthe.Hydrate.meta option: #{inspect(key)}"
        end)

      {:meta, extra_meta ++ entries}
    end

    defp validate!(rule, key) do
      case Rule.validate(rule) do
        :ok -> :ok
        {:error, errors} -> raise ArgumentError, "invalid #{key} rule: #{Enum.join(errors, "; ")}"
      end
    end
  end
end
