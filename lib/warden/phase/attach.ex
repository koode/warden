defmodule Warden.Phase.Attach do
  @moduledoc false
  # Schema pipeline phase. Runs right after `Absinthe.Phase.Schema.InlineFunctions`,
  # which is where Absinthe applies the schema's `middleware/3` callback. Wrapping the
  # middleware here means a user's `middleware/3` cannot remove Warden's entries.

  use Absinthe.Phase

  alias Absinthe.Blueprint
  alias Absinthe.Type

  @doc false
  # Pipeline modifier entry point (`@pipeline_modifier Warden.Phase.Attach`).
  def pipeline(pipeline) do
    pipeline
    |> Enum.map(fn
      # Keep Warden meta across later `{:meta, _}` hydrations (see `Warden.Hydrator`).
      # A schema that configures its own hydrator keeps it.
      {Absinthe.Phase.Schema.Hydrate, opts} ->
        {Absinthe.Phase.Schema.Hydrate, Keyword.put_new(opts, :hydrator, Warden.Hydrator)}

      phase ->
        phase
    end)
    |> Absinthe.Pipeline.insert_after(Absinthe.Phase.Schema.InlineFunctions, __MODULE__)
  end

  @impl Absinthe.Phase
  def run(%Blueprint{schema: schema} = blueprint, _opts) do
    config = Warden.Schema.config!(schema)
    [schema_def] = blueprint.schema_definitions

    types = Map.new(schema_def.type_artifacts, &{&1.identifier, &1})
    plan = Warden.Plan.build(types, config)

    if plan.errors != [] do
      raise CompileError,
        description:
          "Warden found #{length(plan.errors)} problem(s) in #{inspect(schema)}:\n" <>
            Enum.map_join(plan.errors, "\n", &("  * " <> &1))
    end

    artifacts = Enum.map(schema_def.type_artifacts, &apply_plan(&1, plan))
    schema_def = %{schema_def | type_artifacts: artifacts}

    {:ok, %{blueprint | schema_definitions: [schema_def]}}
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
    pre_mw = if pre, do: [Warden.Middleware.pre_spec(pre)], else: []

    case {middleware, post} do
      {_, nil} ->
        pre_mw ++ middleware

      # Middleware that could not be escaped at compile time is expanded at runtime by
      # Absinthe's shim, which replaces the remaining middleware. Warden's own shim calls
      # it and then appends the post middleware again.
      {[{{Absinthe.Middleware, :shim}, shim_args}], post} ->
        pre_mw ++ [Warden.Middleware.shim_spec(shim_args, post)]

      {middleware, post} ->
        pre_mw ++ middleware ++ [Warden.Middleware.post_spec(post)]
    end
  end

  @doc false
  def wrap_config(field, spec) do
    original = Map.get(field, :config)
    %{field | config: Warden.Subscription.config_ref(field.identifier, original, spec)}
  end
end
