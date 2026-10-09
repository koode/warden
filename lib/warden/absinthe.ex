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

    alias Warden.Absinthe.{Config, Plan, Plugin, Verifier}

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
        case Config.validate_options(opts) do
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

        def __warden__(:options), do: unquote(Macro.escape(config))
      end
    end

    @doc false
    defmacro __before_compile__(_env) do
      quote do
        defoverridable plugins: 0

        # Overrides the plugins/0 of the user's schema, so it must stay public; it is
        # hidden from the user's docs like Absinthe's own default plugins/0.
        # credo:disable-for-next-line ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def plugins, do: unquote(Plugin).add_to(super())
      end
    end

    @doc false
    def __after_compile__(env, _bytecode) do
      Verifier.verify!(env.module)
    end

    @doc """
    Returns the authorization plan of a compiled schema: for every field that has Warden
    middleware, the pre and post specs. Meant for debugging and tests.
    """
    @spec plan(module) :: struct()
    def plan(schema) do
      Plan.build(Verifier.compiled_types(schema), Config.config!(schema))
    end
  end
end
