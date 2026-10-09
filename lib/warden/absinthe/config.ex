# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Config do
    @moduledoc false
    # Validates the options of `use Warden.Absinthe` and builds the full configuration
    # (with the authorizer's catalog) at compile time.

    alias Warden.Absinthe.Rules
    alias Warden.Rule

    @option_keys [:authorizer, :strict_mode, :default_object_rule, :introspection, :list_policy]

    @spec validate_options(keyword) :: {:ok, map} | {:error, [String.t()]}
    def validate_options(opts) do
      authorizer = Keyword.get(opts, :authorizer)
      strict = Keyword.get(opts, :strict_mode, false)
      default_rule = Keyword.get(opts, :default_object_rule)
      introspection = Keyword.get(opts, :introspection, :public)
      policy = Keyword.get(opts, :list_policy, :null_item)

      errors =
        unknown_option_errors(opts) ++
          authorizer_errors(authorizer) ++
          strict_mode_errors(strict) ++
          rule_option_errors(:default_object_rule, default_rule) ++
          rule_option_errors(:introspection, introspection) ++
          list_policy_errors(policy)

      case errors do
        [] ->
          {:ok,
           %{
             authorizer: authorizer,
             strict_mode: strict,
             default_object_rule: default_rule,
             introspection: introspection,
             list_policy: policy
           }}

        errors ->
          {:error, errors}
      end
    end

    defp unknown_option_errors(opts) do
      case Keyword.keys(opts) -- @option_keys do
        [] -> []
        unknown -> ["unknown options: #{inspect(unknown)}"]
      end
    end

    defp authorizer_errors(authorizer) when is_atom(authorizer) and authorizer != nil, do: []
    defp authorizer_errors(_), do: ["`:authorizer` must be a module"]

    defp strict_mode_errors(strict) when strict in [false, :root, :all], do: []

    defp strict_mode_errors(strict),
      do: ["`:strict_mode` must be false, :root or :all, got: #{inspect(strict)}"]

    defp rule_option_errors(_key, nil), do: []

    defp rule_option_errors(key, rule) do
      case Rule.validate(rule) do
        :ok -> []
        {:error, errors} -> Enum.map(errors, &"`#{inspect(key)}`: #{&1}")
      end
    end

    defp list_policy_errors(policy) do
      if policy in Rules.list_policies(),
        do: [],
        else: ["`:list_policy` must be one of #{inspect(Rules.list_policies())}"]
    end

    # The full configuration, including the authorizer's catalog. Called at compile time.
    @spec config!(module) :: map
    def config!(schema) do
      options = schema_options!(schema)
      authorizer = options.authorizer
      ensure_authorizer!(authorizer)
      catalog = authorizer.__warden_catalog__()

      extra_errors =
        catalog_errors(:default_object_rule, options.default_object_rule, catalog) ++
          catalog_errors(:introspection, options.introspection, catalog)

      if extra_errors != [] do
        raise CompileError,
          description:
            "invalid Warden.Absinthe options in #{inspect(schema)}:\n" <>
              Enum.map_join(extra_errors, "\n", &("  * " <> &1))
      end

      Map.put(options, :catalog, catalog)
    end

    defp schema_options!(schema) do
      _ = Code.ensure_loaded(schema)

      unless function_exported?(schema, :__warden__, 1) do
        raise CompileError, description: "#{inspect(schema)} does not `use Warden.Absinthe`"
      end

      schema.__warden__(:options)
    end

    defp ensure_authorizer!(authorizer) do
      case Code.ensure_compiled(authorizer) do
        {:module, _} ->
          :ok

        {:error, reason} ->
          raise CompileError,
            description:
              "Warden authorizer #{inspect(authorizer)} could not be loaded: #{inspect(reason)}"
      end

      unless function_exported?(authorizer, :__warden_catalog__, 0) do
        raise CompileError, description: "#{inspect(authorizer)} does not `use Warden.Authorizer`"
      end
    end

    defp catalog_errors(_key, nil, _catalog), do: []

    defp catalog_errors(key, rule, catalog) do
      case Rule.validate(rule, catalog) do
        :ok -> []
        {:error, errors} -> Enum.map(errors, &"`#{inspect(key)}`: #{&1}")
      end
    end
  end
end
