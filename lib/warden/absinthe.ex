# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe do
    @moduledoc """
    Adds Warden authorization to an Absinthe schema.

        defmodule MyApp.Schema do
          use Absinthe.Schema
          use Warden.Absinthe, authorizer: MyApp.Authz   # explicit authorizer

          # ...
        end

        defmodule MyApp.Schema do
          use Absinthe.Schema
          use Warden.Absinthe                            # config :warden, authorizer: MyApp.Authz

          # ...
        end

    `use Warden.Absinthe` must come after `use Absinthe.Schema`. Needs the `absinthe`
    dependency.

    ## Options

      * `:authorizer` - a module that uses `Warden.Authorizer`. Resolution order: this
        option, then the configured default (`config :warden, authorizer: MyApp.Authz`),
        resolved at compile time. With neither, compilation fails with an `ArgumentError`
        that names the fix.
      * `:strict_mode` - `false` (default), `:root` or `:all`. See the README.
      * `:default_object_rule` - rule for object types without their own rule (root and
        introspection types excluded). Default `nil` (none). Setting it to `public()` is a
        no-op that hides missing rules; avoid it.
      * `:introspection` - rule that guards `__schema` and `__type`. Default `public()`.
      * `:list_policy` - default list policy: `:null_item` (default), `:filter` or
        `:fail_list`.

    At compile time Warden validates every rule against the authorizer's catalogs,
    attaches its middleware to every field that needs it, and then verifies the compiled
    schema. Any problem is a `CompileError`.
    """

    alias Warden.Rule

    @option_keys [:authorizer, :strict_mode, :default_object_rule, :introspection, :list_policy]

    defmacro __using__(opts) do
      env = __CALLER__

      if Module.get_attribute(env.module, :absinthe_scope_stack) == nil or
           not Module.has_attribute?(env.module, :pipeline_modifier) do
        raise CompileError,
          file: env.file,
          line: env.line,
          description: "`use Warden.Absinthe` must come after `use Absinthe.Schema`"
      end

      {opts, _} =
        Code.eval_quoted(
          quote do
            import Warden.Rule
            unquote(opts)
          end,
          [],
          env
        )

      # The authorizer comes from the option or the configured default, resolved by the
      # same core function as every other entry point (raises ArgumentError without one).
      opts =
        case Keyword.get(opts, :authorizer) do
          explicit when is_atom(explicit) ->
            Keyword.put(opts, :authorizer, Warden.resolve_authorizer!(explicit))

          _ ->
            opts
        end

      config =
        case validate_options(opts) do
          {:ok, config} ->
            config

          {:error, errors} ->
            raise CompileError,
              file: env.file,
              line: env.line,
              description:
                "invalid Warden.Absinthe options:\n" <>
                  Enum.map_join(errors, "\n", &("  * " <> &1))
        end

      quote do
        use Warden.Absinthe.Notation

        @pipeline_modifier Warden.Absinthe.Phase.Attach
        @before_compile Warden.Absinthe
        @after_compile Warden.Absinthe

        @doc false
        def __warden__(:options), do: unquote(Macro.escape(config))
      end
    end

    @doc false
    defmacro __before_compile__(_env) do
      quote do
        defoverridable plugins: 0

        @doc false
        def plugins, do: Warden.Absinthe.Plugin.add_to(super())
      end
    end

    @doc false
    def __after_compile__(env, _bytecode) do
      Warden.Absinthe.Verifier.verify!(env.module)
    end

    @doc false
    def validate_options(opts) do
      errors = []

      unknown = Keyword.keys(opts) -- @option_keys

      errors =
        if unknown == [], do: errors, else: ["unknown options: #{inspect(unknown)}" | errors]

      authorizer = Keyword.get(opts, :authorizer)

      errors =
        if is_atom(authorizer) and authorizer != nil,
          do: errors,
          else: ["`:authorizer` must be a module" | errors]

      strict = Keyword.get(opts, :strict_mode, false)

      errors =
        if strict in [false, :root, :all],
          do: errors,
          else: ["`:strict_mode` must be false, :root or :all, got: #{inspect(strict)}" | errors]

      default_rule = Keyword.get(opts, :default_object_rule)

      errors =
        case default_rule && Rule.validate(default_rule) do
          r when r in [nil, :ok] -> errors
          {:error, es} -> Enum.map(es, &"`:default_object_rule`: #{&1}") ++ errors
        end

      introspection = Keyword.get(opts, :introspection, :public)

      errors =
        case Rule.validate(introspection) do
          :ok -> errors
          {:error, es} -> Enum.map(es, &"`:introspection`: #{&1}") ++ errors
        end

      policy = Keyword.get(opts, :list_policy, :null_item)

      errors =
        if policy in Rule.list_policies(),
          do: errors,
          else: ["`:list_policy` must be one of #{inspect(Rule.list_policies())}" | errors]

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
          {:error, Enum.reverse(errors)}
      end
    end

    @doc false
    # The full configuration, including the authorizer's catalog. Called at compile time.
    def config!(schema) do
      _ = Code.ensure_loaded(schema)

      unless function_exported?(schema, :__warden__, 1) do
        raise CompileError,
          description: "#{inspect(schema)} does not `use Warden.Absinthe`"
      end

      options = schema.__warden__(:options)
      authorizer = options.authorizer

      case Code.ensure_compiled(authorizer) do
        {:module, _} ->
          :ok

        {:error, reason} ->
          raise CompileError,
            description:
              "Warden authorizer #{inspect(authorizer)} could not be loaded: #{inspect(reason)}"
      end

      unless function_exported?(authorizer, :__warden_catalog__, 0) do
        raise CompileError,
          description: "#{inspect(authorizer)} does not `use Warden.Authorizer`"
      end

      catalog = authorizer.__warden_catalog__()

      extra_errors =
        [
          {:default_object_rule, options.default_object_rule},
          {:introspection, options.introspection}
        ]
        |> Enum.flat_map(fn
          {_, nil} ->
            []

          {key, rule} ->
            case Rule.validate(rule, catalog) do
              :ok -> []
              {:error, es} -> Enum.map(es, &"`#{inspect(key)}`: #{&1}")
            end
        end)

      if extra_errors != [] do
        raise CompileError,
          description:
            "invalid Warden.Absinthe options in #{inspect(schema)}:\n" <>
              Enum.map_join(extra_errors, "\n", &("  * " <> &1))
      end

      Map.put(options, :catalog, catalog)
    end

    @doc """
    Returns the authorization plan of a compiled schema: for every field that has Warden
    middleware, the pre and post specs. Meant for debugging and tests.
    """
    @spec plan(module) :: Warden.Absinthe.Plan.t()
    def plan(schema) do
      Warden.Absinthe.Plan.build(Warden.Absinthe.Verifier.compiled_types(schema), config!(schema))
    end
  end
end
