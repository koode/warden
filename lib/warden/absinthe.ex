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
      * `:batch_across_parents` - `:auto` (default), `true` or `false`: whether the object
        rule of a single object under a list is decided for every parent at once through
        `Absinthe.Middleware.Batch`. See the actors guide.
      * `:require_can_for` - schemas (or struct modules) whose object types must use
        `can/2` with that schema's policy in their object rule. Needs `strict_mode: :all`.
        An object type is linked to a schema by `warden_schema Schema` or by a `can/2`
        rule whose policy is for it; a listed schema no object type is linked to fails
        compilation too.
      * `:warm_actor` - `{module, function}` or a `&Module.function/2` capture, called as
        `function(actor, context)` right after Warden builds the actor of a document
        execution, to fill its cache once: `Warden.Actor.preload_tenant_roles/3`,
        `Warden.Actor.cached_tenants/2`, `Warden.Ecto.preload_ids/4`. The actor it returns
        is the one every rule and `actor/1` of that execution use. It runs once per
        execution: before resolution, at the first field rule where Absinthe runs
        resolution without plugin callbacks, for the subscribe-time checks of a
        subscription, and on every subscription publish. It must return the actor it was
        given with only its cache changed: any other answer, or an actor with another
        instance, subject, kind, roles, permissions, credential, system flag, context,
        delegator or bounds, raises `Warden.PolicyError`. An anonymous function fails
        compilation, since the options are compiled into the schema.

      * `:decision_reuse` - `true` (default) or `false`. With `true`, an object rule
        that reads only the actor, the object and the context (built-in leaves,
        `tenant_role` and `can/2` without arguments, checks declared `per_object: true`)
        is decided once per object within a query or subscription publish and reused
        wherever an equal (`===`) object of the type appears again, under the same
        context as far as the rule reads it; a field without a rule of its own skips Warden's middleware for an
        object that passed its rule. Decisions are the same as with `false`; see
        "Decision reuse" in the README for what it assumes.

    At compile time Warden validates every rule against the authorizer's catalogs,
    attaches its middleware to every field that needs it, and then verifies the compiled
    schema. Any problem is a `CompileError`.
    """

    alias Warden.Absinthe.{Config, Middleware, Plan, Plugin, Verifier}

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
    Returns the actor of the document execution that `resolution` belongs to: the actor
    every Warden rule in that execution is decided for. Warden builds it once, before
    resolution starts, from the execution's context, and warms it with the schema's
    `:warm_actor` function; every subscription publish builds a new one from the
    subscriber's context.

    The actor is read-only here: a resolver cannot hand a warmed actor back. Warm it
    with `:warm_actor` instead, so the rules and the resolvers share one cache and the
    tenants, tenant roles and preloaded ids are read once per execution.

    Use it in a resolver to load rows that the object rules then trust:

        resolve fn _args, resolution ->
          query = from(issue in MyApp.Issues.Issue, order_by: issue.id)
          {:ok, Warden.Ecto.all(MyApp.Repo, query, Warden.Absinthe.actor(resolution), :read)}
        end

    Raises `ArgumentError` when the schema does not `use Warden.Absinthe`, and
    `Warden.PolicyError` when the execution has no actor yet. That happens only where
    Absinthe runs resolution without the schema's plugin callbacks, before any Warden
    rule of the execution ran: `Absinthe.Pipeline.BatchResolver` (Absinthe.Plug's batch
    mode) and a custom pipeline that runs Absinthe's resolution phase with
    `plugin_callbacks: false`.
    """
    @spec actor(Absinthe.Resolution.t()) :: Warden.Actor.t()
    def actor(%Absinthe.Resolution{schema: schema, acc: acc}) do
      if not (is_atom(schema) and function_exported?(schema, :__warden__, 1)) do
        raise ArgumentError, "#{inspect(schema)} does not `use Warden.Absinthe`"
      end

      case Middleware.stored_actor(acc) do
        %Warden.Actor{} = actor ->
          actor

        nil ->
          raise Warden.PolicyError, """
          the document execution has no Warden actor yet: it runs without the schema's \
          plugin callbacks (Absinthe.Pipeline.BatchResolver, or plugin_callbacks: false), \
          so Warden builds the actor at the first field rule instead\
          """
      end
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
