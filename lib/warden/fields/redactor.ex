defmodule Warden.Fields.Redactor do
  @moduledoc false
  # Applies field policies. Any module that exports `__warden_fields__(:info)`, returning
  # `%{authorizer: module, for: module, struct_fields: [atom],
  # redactions: [%{field: atom, with: term, rule: rule}]}`, is a field policy;
  # `use Warden.Fields` generates it.

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
end
