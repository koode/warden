# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Phase.Attach do
    @moduledoc false
    # Schema pipeline phase. Runs right after `Absinthe.Phase.Schema.InlineFunctions`,
    # which is where Absinthe applies the schema's `middleware/3` callback. Wrapping the
    # middleware here means a user's `middleware/3` cannot remove Warden's entries.

    use Absinthe.Phase

    alias Absinthe.Blueprint
    alias Absinthe.Type
    alias Warden.Absinthe.{Config, Middleware, Plan, SubscriptionConfig}

    # Pipeline modifier entry point (`@pipeline_modifier Warden.Absinthe.Phase.Attach`).
    def pipeline(pipeline) do
      pipeline
      |> Enum.map(fn
        # Keep Warden meta across later `{:meta, _}` hydrations (see `Warden.Absinthe.Hydrator`).
        # A schema that configures its own hydrator keeps it.
        {Absinthe.Phase.Schema.Hydrate, opts} ->
          {Absinthe.Phase.Schema.Hydrate,
           Keyword.put_new(opts, :hydrator, Warden.Absinthe.Hydrator)}

        phase ->
          phase
      end)
      |> Absinthe.Pipeline.insert_after(Absinthe.Phase.Schema.InlineFunctions, __MODULE__)
    end

    @impl Absinthe.Phase
    def run(%Blueprint{schema: schema} = blueprint, _opts) do
      config = Config.config!(schema)
      [schema_def] = blueprint.schema_definitions

      types = Map.new(schema_def.type_artifacts, &{&1.identifier, &1})
      plan = Plan.build(types, config)

      if plan.errors != [] do
        raise CompileError,
          description:
            "Warden found #{length(plan.errors)} problem(s) in #{inspect(schema)}:\n" <>
              Enum.map_join(plan.errors, "\n", &("  * " <> &1))
      end

      warn_unguarded_mutations(schema, types, plan)
      warn_unguarded_subscriptions(schema, types, plan)

      artifacts = Enum.map(schema_def.type_artifacts, &apply_plan(&1, plan))
      schema_def = %{schema_def | type_artifacts: artifacts}

      {:ok, %{blueprint | schema_definitions: [schema_def]}}
    end

    # An object rule on a mutation's return type only nulls the result: the resolver has
    # already run. Warn about mutations that have nothing else (no root, field or
    # argument rule) to stop them. An explicit `authorize public()` on the mutation field
    # states that anyone may run it and silences the warning.
    defp warn_unguarded_mutations(schema, types, plan) do
      mutation = Map.get(types, :mutation)

      for {{:mutation, fident}, {nil, post}} <- Enum.sort(plan.fields),
          post != nil,
          field = mutation && Map.get(mutation.fields, fident),
          Type.meta(field, :warden_rule) == nil do
        name = field.name

        IO.warn(
          "Warden: mutation #{inspect(name)} in #{inspect(schema)} is protected only by the " <>
            "object rule of its return type, which runs after the resolver. The mutation runs " <>
            "for any caller; add a field rule (authorize) to stop it before it runs.",
          []
        )
      end

      :ok
    end

    # A subscription whose return type has a value-dependent object rule is decided only
    # at publish time. Absinthe's own publish loop pushes a denied payload as `null`, so
    # the subscriber still learns that an object exists, and when it changes; only a
    # pubsub that delegates `run_docset/3` to `Warden.Absinthe.Subscription` pushes
    # nothing, and the schema cannot tell which pubsub an app uses. Warn about
    # subscriptions with nothing to refuse the subscribe (no field or argument rule; an
    # explicit `authorize public()` acknowledges it); `can(Policy, :read, arg: [:id])` on
    # the field refuses it for an object the subscriber may not read.
    defp warn_unguarded_subscriptions(schema, types, plan) do
      subscription = Map.get(types, :subscription)
      fields = if subscription, do: Enum.sort_by(subscription.fields, &elem(&1, 0)), else: []

      for {_fident, field} <- fields,
          not String.starts_with?(field.name, "__"),
          not guarded_field?(field),
          Plan.value_dependent?(return_rule(field, types, plan)) do
        IO.warn(
          """
          Warden: subscription #{inspect(field.name)} in #{inspect(schema)} is protected \
          only by the object rule of its return type, which reads the value: unless the \
          pubsub delegates `run_docset/3` to `Warden.Absinthe.Subscription`, a subscriber \
          who may not see an object still gets an event (with no data) whenever it is \
          published. Add a field rule that refuses the subscribe, such as \
          `authorize can(Policy, :read, arg: [:id])`.\
          """,
          []
        )
      end

      :ok
    end

    defp guarded_field?(field) do
      arg_rules =
        for {_ident, arg} <- field.args || %{}, Type.meta(arg, :warden_rule) != nil, do: arg

      Type.meta(field, :warden_rule) != nil or
        Type.meta(field, :warden_args) not in [nil, %{}] or arg_rules != []
    end

    defp return_rule(field, types, plan) do
      named = Type.unwrap(field.type)

      case Map.get(types, named) do
        %Type.Object{} -> Map.get(plan.object_rules, named)
        %{} -> Map.get(plan.object_rules, named) || any_member_rule(types, named, plan)
        nil -> nil
      end
    end

    defp any_member_rule(types, named, plan) do
      members =
        case Map.get(types, named) do
          %Type.Union{types: members} -> members
          _interface -> Plan.implementors(types, named)
        end

      Enum.find_value(
        members,
        &(Plan.value_dependent?(Map.get(plan.object_rules, &1)) && Map.get(plan.object_rules, &1))
      )
    end

    defp apply_plan(%Type.Object{identifier: ident, fields: fields} = object, plan) do
      fields =
        Map.new(fields, fn {fident, field} ->
          field =
            case Map.fetch(plan.fields, {ident, fident}) do
              {:ok, {pre, post}} -> %{field | middleware: wrap(field.middleware, pre, post)}
              :error -> field
            end

          field =
            case {ident, Map.fetch(plan.subscriptions, fident)} do
              {:subscription, {:ok, spec}} -> wrap_config(field, spec)
              _ -> field
            end

          {fident, field}
        end)

      %{object | fields: fields}
    end

    defp apply_plan(type, _plan), do: type

    def wrap(middleware, pre, post) do
      pre_mw = if pre, do: [Middleware.pre_spec(pre)], else: []

      case {middleware, post} do
        {_, nil} ->
          pre_mw ++ middleware

        # Middleware that could not be escaped at compile time is expanded at runtime by
        # Absinthe's shim, which replaces the remaining middleware. Warden's own shim calls
        # it and then appends the post middleware again.
        {[{{Absinthe.Middleware, :shim}, shim_args}], post} ->
          pre_mw ++ [Middleware.shim_spec(shim_args, post)]

        {middleware, post} ->
          pre_mw ++ middleware ++ [Middleware.post_spec(post)]
      end
    end

    def wrap_config(field, spec) do
      original = Map.get(field, :config)
      %{field | config: SubscriptionConfig.config_ref(field.identifier, original, spec)}
    end
  end
end
