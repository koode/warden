# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.RequireCan do
    @moduledoc false
    # The verifier check behind `require_can_for: [Schema, ...]`: an object type linked to
    # a listed schema (by `warden_schema Schema`, or by a `can/2` rule whose policy is for
    # that schema) must use `can/2` with that schema's policy in its object rule, so the
    # rows GraphQL returns are checked by the same declaration as the query scope. A
    # listed schema that no object type is linked to fails too: the option would guard
    # nothing.

    alias Absinthe.Type

    @spec errors(map, map, map) :: [String.t()]
    def errors(_types, _plan, %{require_can_for: []}), do: []

    def errors(types, plan, %{require_can_for: required}) do
      linked =
        for {ident, %Type.Object{} = object} <- Enum.sort_by(types, &elem(&1, 0)),
            not String.starts_with?(object.name, "__"),
            do: {object, policy_schemas(Map.get(plan.object_rules, ident)), declared(object)}

      object_errors =
        for {object, from_rule, declared} <- linked,
            schema <- declared,
            schema in required,
            schema not in from_rule do
          """
          #{object.name}: its values are #{inspect(schema)} (warden_schema), so its object \
          rule must use can/2 with #{inspect(schema)}'s policy (require_can_for)\
          """
        end

      covered =
        Enum.flat_map(linked, fn {_object, from_rule, declared} -> from_rule ++ declared end)

      unlinked =
        for schema <- required, schema not in covered do
          """
          `require_can_for` lists #{inspect(schema)}, but no object type declares \
          `warden_schema #{inspect(schema)}` or uses can/2 with its policy\
          """
        end

      object_errors ++ unlinked
    end

    defp declared(object) do
      case Type.meta(object, :warden_schema) do
        nil -> []
        schema -> [schema]
      end
    end

    # The `for:` of every policy the rule names with `can/2,3`.
    defp policy_schemas(rule) do
      for {:can, policy, _action, _opts} <- leaves(rule),
          is_atom(policy),
          match?({:module, _module}, Code.ensure_compiled(policy)),
          function_exported?(policy, :__warden_policy__, 1),
          do: policy.__warden_policy__(:info).for
    end

    defp leaves({tag, rules}) when tag in [:all, :any] and is_list(rules),
      do: Enum.flat_map(rules, &leaves/1)

    defp leaves(nil), do: []
    defp leaves(rule), do: [rule]
  end
end
