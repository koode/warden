defmodule Warden.Verifier do
  @moduledoc false
  # Runs after the schema module and its compiled types exist. Recomputes the plan from
  # the compiled types and checks, in both directions, that every field carries exactly
  # the Warden middleware the plan requires (and none where it requires none), and that
  # every subscription field's `config` is wrapped.

  alias Absinthe.Type
  alias Warden.Middleware

  def verify!(schema) do
    case verify(schema) do
      :ok ->
        :ok

      {:error, errors} ->
        raise CompileError,
          description:
            "Warden verification failed for #{inspect(schema)}:\n" <>
              Enum.map_join(errors, "\n", &("  * " <> &1))
    end
  end

  def verify(schema) do
    config = Warden.Schema.config!(schema)
    types = compiled_types(schema)
    plan = Warden.Plan.build(types, config)

    errors =
      plan.errors ++
        for(
          {_, %Type.Object{} = object} <- Enum.sort_by(types, &elem(&1, 0)),
          {_, field} <- Enum.sort_by(object.fields, &elem(&1, 0)),
          error <- check_field(object, field, plan),
          do: error
        ) ++ check_subscriptions(types, plan)

    if errors == [], do: :ok, else: {:error, errors}
  end

  def compiled_types(schema) do
    schema.__absinthe_types__(:all)
    |> Map.keys()
    |> Enum.flat_map(fn ident ->
      case Absinthe.Schema.lookup_type(schema, ident) do
        nil -> []
        type -> [{ident, type}]
      end
    end)
    |> Map.new()
  end

  defp check_field(object, field, plan) do
    where = "#{object.name}.#{field.name}"

    {expected_pre, expected_post} =
      Map.get(plan.fields, {object.identifier, field.identifier}, {nil, nil})

    middleware = List.wrap(field.middleware)

    {actual_pre, rest} =
      case middleware do
        [{{Middleware, :pre}, spec} | rest] -> {spec, rest}
        rest -> {nil, rest}
      end

    {actual_post, middle} =
      case List.last(rest) do
        {{Middleware, :post}, spec} -> {spec, Enum.drop(rest, -1)}
        {{Middleware, :shim}, {_, spec}} -> {spec, Enum.drop(rest, -1)}
        _ -> {nil, rest}
      end

    [
      if(actual_pre != expected_pre,
        do:
          "#{where}: pre middleware #{describe(actual_pre)}, plan requires #{describe(expected_pre)}"
      ),
      if(actual_post != expected_post,
        do:
          "#{where}: post middleware #{describe(actual_post)}, plan requires #{describe(expected_post)}"
      ),
      if(Enum.any?(middle, &Middleware.warden_entry?/1),
        do: "#{where}: Warden middleware found in an unexpected position"
      )
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp check_subscriptions(types, plan) do
    case Map.get(types, :subscription) do
      %Type.Object{fields: fields} ->
        for {ident, field} <- Enum.sort_by(fields, &elem(&1, 0)),
            Map.has_key?(plan.subscriptions, ident),
            expected = Map.fetch!(plan.subscriptions, ident),
            not match?({:ref, Warden.Subscription, {:config, ^ident, _, ^expected}}, field.config) do
          "Subscription.#{field.name}: config is not wrapped by Warden"
        end

      _ ->
        []
    end
  end

  defp describe(nil), do: "absent"
  defp describe(_), do: "present"
end
