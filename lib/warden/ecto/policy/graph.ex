# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Policy.Graph do
    @moduledoc false
    # Checks what a policy's clauses need from other policies: every `through`,
    # `through_any` and `through_type` target has a `Warden.Ecto.Policy` of the same
    # authorizer with the action, tenancy matches (both tenanted or both not), and no
    # chain of `{policy, action}` leads back to itself.
    #
    # The policies of a project compile in parallel and only name each other at runtime,
    # so this runs after the whole project has compiled (`@after_verify`, as compiler
    # warnings) and once per policy on first use (raising `Warden.PolicyError`).

    alias Warden.Ecto.Info

    @spec after_verify(module) :: :ok
    def after_verify(policy) do
      for error <- validate(policy) do
        IO.warn("#{inspect(policy)}: #{error}", [])
      end

      :ok
    end

    # Raises `Warden.PolicyError` unless the policy's graph is valid. A valid result is
    # remembered for the life of the VM; an invalid one is checked again (and raises) on
    # every use.
    @spec ensure_valid!(module) :: :ok
    def ensure_valid!(policy) do
      key = {__MODULE__, policy}

      if :persistent_term.get(key, false) do
        :ok
      else
        case validate(policy) do
          [] ->
            :persistent_term.put(key, true)

          errors ->
            raise Warden.PolicyError,
                  "invalid policy #{inspect(policy)}:\n" <>
                    Enum.map_join(errors, "\n", &("  * " <> &1))
        end
      end
    end

    @spec validate(module) :: [String.t()]
    def validate(policy) do
      info = Info.fetch!(policy)

      graph_errors =
        info.actions
        |> Map.keys()
        |> Enum.sort()
        |> Enum.flat_map(&visit(info, &1, [{policy, &1}]))

      Enum.uniq(duplicate_errors(info) ++ graph_errors)
    end

    # One struct has one policy in an authorizer: with two, which one decides a row would
    # depend on their order in `policies:`.
    defp duplicate_errors(info) do
      others =
        for other <- info.authorizer.__warden_catalog__().policies,
            other != info.policy,
            Code.ensure_loaded?(other),
            function_exported?(other, :__warden_policy__, 1),
            other.__warden_policy__(:info).for == info.schema,
            do: other

      case others do
        [] ->
          []

        _duplicates ->
          names = Enum.map_join(others, ", ", &inspect/1)

          [
            "#{inspect(info.schema)} has another policy in #{inspect(info.authorizer)}'s `policies:`: #{names}"
          ]
      end
    end

    defp visit(info, action, path) do
      case Map.fetch!(info.actions, action) do
        :scope ->
          []

        {:clauses, requires, allows} ->
          for clause <- requires ++ allows,
              part <- clause.parts,
              target <- targets(info, part, action),
              error <- target_errors(info, target, path),
              do: error
      end
    end

    # `{label, related_schema | {:policy, module}, action}` for every part that leads to
    # another policy.
    defp targets(info, {:through, assoc, through_action, _if_nil, _opts}, action),
      do: [{"through: #{inspect(assoc)}", related(info, assoc), through_action || action}]

    defp targets(info, {:through_any, assoc, through_action}, action),
      do: [{"through_any: #{inspect(assoc)}", related(info, assoc), through_action || action}]

    defp targets(_info, {:through_type, {_type_field, _id_field, policies}}, action) do
      for {type, {policy, type_action}} <- Enum.sort(policies) do
        {"through_type #{inspect(type)}", {:policy, policy}, type_action || action}
      end
    end

    defp targets(_info, _part, _action), do: []

    defp related(info, assoc), do: info.schema.__schema__(:association, assoc).related

    defp target_errors(info, {label, target, action}, path) do
      case parent_policy(info, target) do
        {:ok, parent} -> parent_errors(info, parent, label, action, path)
        {:error, error} -> ["#{label}: #{error}"]
      end
    end

    defp parent_policy(_info, {:policy, policy}) do
      if Info.ecto_policy?(policy),
        do: {:ok, Info.fetch!(policy)},
        else: {:error, "#{inspect(policy)} is not a Warden.Ecto.Policy"}
    end

    defp parent_policy(info, schema) do
      case Warden.Policy.policy_for(info.authorizer, schema) do
        nil ->
          {:error,
           "#{inspect(schema)} has no policy in #{inspect(info.authorizer)}'s `policies:`"}

        policy ->
          parent_policy(info, {:policy, policy})
      end
    end

    defp parent_errors(info, parent, label, action, path) do
      step = {parent.policy, action}
      cycle = step in path

      errors =
        [
          parent.authorizer != info.authorizer &&
            "#{label}: #{inspect(parent.policy)} belongs to #{inspect(parent.authorizer)}",
          not Map.has_key?(parent.actions, action) &&
            "#{label}: #{inspect(parent.policy)} has no action #{inspect(action)}",
          info.tenant == nil != (parent.tenant == nil) &&
            """
            #{label}: #{inspect(info.policy)} and #{inspect(parent.policy)} must both have \
            a `:tenant` or both have none, so a parent is never in another tenant\
            """,
          cycle && "#{label}: a through cycle: #{describe(Enum.reverse([step | path]))}"
        ]
        |> Enum.filter(&is_binary/1)

      if errors == [] and not cycle,
        do: visit(parent, action, [step | path]),
        else: errors
    end

    defp describe(path) do
      Enum.map_join(path, " -> ", fn {policy, action} ->
        "#{inspect(policy)} #{inspect(action)}"
      end)
    end
  end
end
