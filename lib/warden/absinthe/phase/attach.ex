defmodule Warden.Absinthe.Phase.Attach do
  @moduledoc false
  # Schema pipeline phase. Runs right after `Absinthe.Phase.Schema.InlineFunctions`,
  # which is where Absinthe applies the schema's `middleware/3` callback. Wrapping the
  # middleware here means a user's `middleware/3` cannot remove Warden's entries.

  use Absinthe.Phase

  alias Absinthe.Blueprint
  alias Absinthe.Type
  alias Warden.Absinthe.Middleware

  @doc false
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
    config = Warden.Absinthe.config!(schema)
    [schema_def] = blueprint.schema_definitions

    types = Map.new(schema_def.type_artifacts, &{&1.identifier, &1})
    plan = Warden.Absinthe.Plan.build(types, config)

    if plan.errors != [] do
      raise CompileError,
        description:
          "Warden found #{length(plan.errors)} problem(s) in #{inspect(schema)}:\n" <>
            Enum.map_join(plan.errors, "\n", &("  * " <> &1))
    end

    warn_unguarded_mutations(schema, types, plan)

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

  @doc false
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

  @doc false
  def wrap_config(field, spec) do
    original = Map.get(field, :config)
    %{field | config: Warden.Absinthe.Subscription.config_ref(field.identifier, original, spec)}
  end
end
