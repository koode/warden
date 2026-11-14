# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Guard do
    @moduledoc false
    # Checks on the queries `Warden.Ecto` scopes and writes through:
    #
    #   * `compose!/1` - a query `scope/4` cannot scope as a whole: combinations (`union`,
    #     `union_all`, `intersect`, `except`), whose other arms would stay unscoped, and
    #     preloads, whose rows would be loaded without the child's policy;
    #   * `ctes!/1` - a CTE named like a table the scope reads: Postgres resolves an
    #     unqualified name to the CTE first, so the CTE would replace the policy's rows;
    #   * `mark/3` and `write!/3` - the marker `scope/4` puts on its `where`, and the checks
    #     of `update_all/4` and `delete_all/3`: a write scope of the root's policy, nothing
    #     that widens it afterwards, no shadowing CTE, and no update of the tenant field or
    #     of a field a write clause goes `through`.

    alias Warden.Ecto.Info

    @marker "warden:scope"
    @update_ops [:set, :inc, :push, :pull]

    @spec compose!(Ecto.Query.t()) :: :ok
    def compose!(%Ecto.Query{combinations: [_combination | _rest]}) do
      raise ArgumentError, """
      Warden.Ecto.scope/4 does not scope a query with union, union_all, intersect or \
      except: scope each arm, then combine them\
      """
    end

    def compose!(%Ecto.Query{preloads: preloads, assocs: assocs})
        when preloads != [] or assocs != [] do
      raise ArgumentError, """
      Warden.Ecto.scope/4 does not scope a query with preloads, which would load the \
      children without their policy; preload a scoped query instead: \
      preload(comments: ^Warden.Ecto.scope(Comment, actor, :read))\
      """
    end

    def compose!(%Ecto.Query{}), do: :ok

    # The `where` that `scope/4` adds carries a marker as its source file.
    @spec mark(Ecto.Query.t(), module, atom) :: Ecto.Query.t()
    def mark(query, policy, action) do
      marker = "#{@marker}:#{policy}:#{action}"
      wheres = List.update_at(query.wheres, -1, &%{&1 | file: marker})
      %{query | wheres: wheres}
    end

    # Raises when a CTE of the query is named like the root's table or a table that a
    # Warden scope of the query reads (through every subquery of its `where`).
    @spec ctes!(Ecto.Query.t()) :: :ok
    def ctes!(%Ecto.Query{with_ctes: nil}), do: :ok

    def ctes!(%Ecto.Query{with_ctes: %{queries: ctes}} = query) do
      names = MapSet.new(ctes, &to_string(elem(&1, 0)))
      read = scope_tables(query)

      case Enum.filter(read, &MapSet.member?(names, &1)) do
        [] ->
          :ok

        shadowed ->
          raise Warden.PolicyError, """
          the query has CTEs named like tables its Warden scope reads \
          (#{Enum.join(Enum.sort(shadowed), ", ")}), which would replace the policy's rows\
          """
      end
    end

    defp scope_tables(query) do
      marked = Enum.filter(query.wheres, &marker?(&1.file))
      root = source_tables(query.from.source)

      nested =
        for where <- marked,
            subquery <- where.subqueries,
            table <- tables(subquery.query),
            do: table

      Enum.uniq(root ++ nested)
    end

    # Every table a (sub)query reads: its source, its joins and the subqueries of its
    # conditions.
    defp tables(%Ecto.Query{} = query) do
      from = source_tables(query.from.source)
      joins = Enum.flat_map(query.joins, &(source_tables(&1.source) ++ expr_tables(&1.on)))
      wheres = Enum.flat_map(query.wheres, &expr_tables/1)
      from ++ joins ++ wheres
    end

    defp expr_tables(%{subqueries: subqueries}), do: Enum.flat_map(subqueries, &tables(&1.query))
    defp expr_tables(_expr), do: []

    defp source_tables({table, _schema}) when is_binary(table), do: [table]
    defp source_tables(%Ecto.SubQuery{query: query}), do: tables(query)
    defp source_tables(_fragment_or_values), do: []

    defp marker?(file) when is_binary(file), do: String.starts_with?(file, @marker <> ":")
    defp marker?(_file), do: false

    # Raises unless the query is a write scope of its root's policy that nothing widened,
    # without a shadowing CTE, and `updates` (with the query's own `update`) change no
    # protected field.
    @spec write!(Ecto.Query.t(), keyword, String.t()) :: :ok
    def write!(%Ecto.Query{} = query, updates, function) do
      schema = root_schema(query)
      scopes = write_scopes(query, schema)

      if scopes == [] do
        raise Warden.PolicyError, """
        Warden.Ecto.#{function} refuses a query that Warden.Ecto.scope/4 did not scope for \
        one of the policy's write_actions (or that was widened afterwards with or_where)\
        """
      end

      ctes!(query)
      protected!(query, updates, scopes, function)
    end

    def write!(_other, _updates, function) do
      raise ArgumentError, "Warden.Ecto.#{function} expects an Ecto query"
    end

    defp root_schema(%Ecto.Query{from: %{source: {_table, schema}}}) when is_atom(schema),
      do: schema

    defp root_schema(_query), do: nil

    # The `{info, action}` of every write marker whose scope still holds: no `or_where`
    # after it and no combinations.
    defp write_scopes(%Ecto.Query{combinations: [_combination | _rest]}, _schema), do: []
    defp write_scopes(_query, nil), do: []

    defp write_scopes(query, schema) do
      query.wheres
      |> Enum.with_index()
      |> Enum.flat_map(fn {where, index} ->
        later = Enum.drop(query.wheres, index + 1)
        holding = Enum.all?(later, &(&1.op == :and))

        case write_marker(where.file, schema) do
          {:ok, scope} when holding -> [scope]
          _not_holding -> []
        end
      end)
    end

    defp write_marker(file, schema) when is_binary(file) do
      with ["warden", "scope", policy, action] <- String.split(file, ":", parts: 4),
           {:ok, policy} <- existing_atom(policy),
           {:ok, action} <- existing_atom(action),
           true <- Info.ecto_policy?(policy),
           info = Info.fetch!(policy),
           true <- info.schema == schema and action in info.write_actions do
        {:ok, {info, action}}
      else
        _not_a_write_marker -> :error
      end
    end

    defp write_marker(_file, _schema), do: :error

    defp existing_atom(string) do
      {:ok, String.to_existing_atom(string)}
    rescue
      ArgumentError -> :error
    end

    defp protected!(query, updates, scopes, function) do
      fields = MapSet.new(updated_fields(updates) ++ query_updated_fields(query))

      protected =
        scopes
        |> Enum.flat_map(fn {info, action} -> protected_fields(info, action) end)
        |> MapSet.new()

      case fields |> MapSet.intersection(protected) |> Enum.sort() do
        [] ->
          :ok

        changed ->
          raise Warden.PolicyError, """
          Warden.Ecto.#{function} refuses to update #{Enum.map_join(changed, ", ", &inspect/1)}: \
          the tenant field and the fields a write clause goes through decide which rows \
          the scope admits\
          """
      end
    end

    defp updated_fields(updates) when is_list(updates) do
      for {op, changes} <- updates,
          op in @update_ops,
          is_list(changes),
          {field, _value} <- changes,
          do: field
    end

    defp updated_fields(_updates), do: []

    defp query_updated_fields(query), do: Enum.flat_map(query.updates, &updated_fields(&1.expr))

    # The tenant field, and the foreign keys (and type fields) of the action's `through:`
    # and `through_type:` clauses.
    defp protected_fields(info, action) do
      tenant = List.wrap(info.tenant)

      through =
        case Map.fetch!(info.actions, action) do
          :scope ->
            []

          {:clauses, requires, allows} ->
            for clause <- requires ++ allows,
                part <- clause.parts,
                field <- part_fields(info, part),
                do: field
        end

      tenant ++ through
    end

    defp part_fields(info, {:through, assoc, _action, _if_nil, _opts}),
      do: [info.schema.__schema__(:association, assoc).owner_key]

    defp part_fields(_info, {:through_type, {type_field, id_field, _targets}}),
      do: [type_field, id_field]

    defp part_fields(_info, _part), do: []
  end
end
