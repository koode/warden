# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Test.Absinthe do
    @moduledoc """
    Runs the cells of a policy matrix through GraphQL, so object rules and `redact_with`
    are proven to agree with the policies (needs `absinthe`).

        test "GraphQL agrees with the policies", %{warden_matrix: matrix} do
          Warden.Test.Absinthe.assert_matrix_matches(MyAppWeb.Schema,
            matrix: matrix,
            query_for: %{
              issue: "query($id: ID!) { issue(id: $id) { id title } }",
              comment: "query($id: ID!) { comment(id: $id) { id body } }"
            }
          )
        end
    """

    alias Absinthe.Adapter.LanguageConventions
    alias Absinthe.Type
    alias Warden.Rule
    alias Warden.Test.Cells

    @default_action :read

    @doc """
    For every GraphQL type in `query_for:`, every resource of a struct the type is linked
    to (by `warden_schema` or a `can/2` object rule) and every actor that is a context
    map, runs the type's document with `Absinthe.run/3` (variable `id` = the row's
    primary key, as a string) and the actor's context, and asserts:

      * the root field returns the object exactly when the resource's policy allows
        `action` (default `:read`), so a missing or weaker object rule fails;
      * when it does, every selected field that `Warden.redact/3` changes for the actor
        holds the redacted value (`nil`, strings, booleans and integers are compared).

    `%Warden.Actor{}` fixtures (system actors, delegated actors) are left out: GraphQL
    builds its actor from the context. Failures raise `ExUnit.AssertionError` naming the
    cells, never row data.

    Options:

      * `:query_for` (required) - `%{type_identifier => document}`;
      * `:matrix` - a `Warden.Test.Matrix` (the `:warden_matrix` of the test context), or
        `:authorizer`, `:actors` and `:resources` (named lists, as in
        `Warden.Test.assert_policy_consistent/4`);
      * `:action` - the policy action the object rules guard, default `:read`;
      * `:adapter` - the Absinthe adapter for field names, default
        `Absinthe.Adapter.LanguageConventions`.
    """
    @spec assert_matrix_matches(module, keyword) :: :ok
    def assert_matrix_matches(schema, opts) when is_atom(schema) and is_list(opts) do
      query_for = Keyword.fetch!(opts, :query_for)
      {authorizer, actors, resources} = cells(opts)
      action = Keyword.get(opts, :action, @default_action)
      adapter = Keyword.get(opts, :adapter, LanguageConventions)
      context_actors = for {name, context} <- actors, not is_struct(context), do: {name, context}
      run = %{schema: schema, authorizer: authorizer, action: action, adapter: adapter}

      problems =
        for {type, document} <- Enum.sort(query_for),
            problem <- type_problems(run, type, document, context_actors, resources),
            do: problem

      if problems != [] do
        lines = Enum.map_join(problems, "\n", &("  " <> &1))
        message = "GraphQL disagrees with the policies in #{length(problems)} cell(s):\n#{lines}"
        raise ExUnit.AssertionError, message: message
      end

      :ok
    end

    defp cells(opts) do
      case Keyword.fetch(opts, :matrix) do
        {:ok, %{authorizer: authorizer, actors: actors, resources: resources}} ->
          {authorizer, actors, resources}

        :error ->
          actors = opts |> Keyword.fetch!(:actors) |> Cells.named("actor")
          resources = opts |> Keyword.fetch!(:resources) |> Cells.named("row")
          {Keyword.fetch!(opts, :authorizer), actors, resources}
      end
    end

    defp type_problems(run, type, document, actors, resources) do
      object =
        Absinthe.Schema.lookup_type(run.schema, type) ||
          raise(ArgumentError, "no GraphQL type #{inspect(type)}")

      linked = linked_structs(object)
      rows = for {name, %struct{} = row} <- resources, struct in linked, do: {name, row}

      if rows == [] do
        ["type #{inspect(type)}: no resource of #{inspect(linked)}"]
      else
        for {actor_name, context} <- actors,
            {row_name, row} <- rows,
            problem <- cell_problems(run, document, context, row),
            do: "#{Cells.cell(actor_name, row_name)}, type #{inspect(type)}: #{problem}"
      end
    end

    defp cell_problems(run, document, context, %struct{} = row) do
      case Warden.Policy.policy_for(run.authorizer, row) do
        nil -> ["#{inspect(struct)} has no policy in #{inspect(run.authorizer)}"]
        policy -> run_cell(run, document, context, row, policy)
      end
    end

    defp run_cell(run, document, context, row, policy) do
      rule = Rule.can(policy, run.action)
      expected = Warden.allowed?(context, rule, value: row, authorizer: run.authorizer)
      variables = %{"id" => to_string(primary_key(row))}
      {:ok, result} = Absinthe.run(document, run.schema, context: context, variables: variables)
      value = root_value(result)

      cond do
        expected and value == nil ->
          ["the policy allows #{inspect(run.action)}, GraphQL returned null"]

        not expected and value != nil ->
          ["the policy denies #{inspect(run.action)}, GraphQL returned the object"]

        value == nil ->
          []

        true ->
          redaction_problems(run, context, row, value)
      end
    end

    defp root_value(%{data: data}) when is_map(data) do
      case Map.values(data) do
        [value] -> value
        _other -> nil
      end
    end

    defp root_value(_result), do: nil

    defp redaction_problems(run, context, row, value) do
      redacted = Warden.redact(context, row, authorizer: run.authorizer)

      for {field, original} <- Map.from_struct(row),
          expected = Map.get(redacted, field),
          expected != original,
          comparable?(expected),
          name = run.adapter.to_external_name(Atom.to_string(field), :field),
          Map.has_key?(value, name),
          Map.fetch!(value, name) != expected,
          do: "field #{inspect(field)} is not redacted"
    end

    defp comparable?(value),
      do: is_nil(value) or is_binary(value) or is_boolean(value) or is_integer(value)

    defp primary_key(%struct{} = row) do
      key =
        if function_exported?(struct, :__schema__, 1),
          do: struct.__schema__(:primary_key) |> List.first(),
          else: :id

      Map.fetch!(row, key)
    end

    # The structs a GraphQL type is about: its `warden_schema`, and the `for:` of every
    # policy its object rule names with `can/2,3`.
    defp linked_structs(object) do
      from_rule =
        for {:can, policy, _action, _opts} <- leaves(Type.meta(object, :warden_rule)),
            Code.ensure_loaded?(policy),
            function_exported?(policy, :__warden_policy__, 1),
            do: policy.__warden_policy__(:info).for

      declared = List.wrap(Type.meta(object, :warden_schema))
      Enum.uniq(declared ++ from_rule)
    end

    defp leaves({tag, rules}) when tag in [:all, :any] and is_list(rules),
      do: Enum.flat_map(rules, &leaves/1)

    defp leaves(nil), do: []
    defp leaves(rule), do: [rule]
  end
end
