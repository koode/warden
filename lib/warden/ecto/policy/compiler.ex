# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Policy.Compiler do
    @moduledoc false
    # Compile-time validation for `use Warden.Ecto.Policy`: the options, every `allow` and
    # `requires` clause, and which actions use a hand-written `scope/4`. Everything that
    # can be known from the policy module and its schema alone fails compilation here.
    # What depends on other policies (a `through` target without a policy, a cycle over
    # several policies) is checked by `Warden.Ecto.Policy.Graph`.

    alias Ecto.Association.{BelongsTo, Has, ManyToMany}
    alias Warden.Policy

    @ecto_option_keys [:schema, :as, :null_tenant, :repo, :subject_id, :write_actions]
    @core_option_keys [:authorizer, :actions, :tenant, :system_kinds]

    # Clause keys that say something about the actor. An `allow` clause needs one, so a
    # clause about rows alone (`where:` only) never admits every actor by accident; a
    # clause meant for everyone says `rule: public()`.
    @actor_keys [:rule, :through, :through_any, :through_type, :actor_in, :member_of] ++
                  [:grant, :within, :when]
    @row_keys [:where, :none, :if_nil]
    @clause_keys @actor_keys ++ @row_keys

    # Field types whose Elixir equality is the database's equality, so `where:`,
    # `actor_in:` and `within:` can be decided on a loaded struct.
    @exact_types [:id, :binary_id, :integer, :boolean, :string, :binary, Ecto.UUID]

    @if_nil_values [:deny, :tenant]

    @spec option_keys() :: [atom]
    def option_keys, do: @core_option_keys ++ @ecto_option_keys

    @spec clause_keys() :: [atom]
    def clause_keys, do: @clause_keys

    # Validates the options. Returns `{:ok, core_info, options}` or `{:error, errors}`.
    @spec validate_options(term, module) :: {:ok, map, map} | {:error, [String.t()]}
    def validate_options(opts, module) when is_list(opts) do
      case Keyword.keys(opts) -- Enum.uniq(Keyword.keys(opts)) do
        [] -> validate_unique_options(opts, module)
        twice -> {:error, ["options given twice: #{inspect(Enum.uniq(twice))}"]}
      end
    end

    def validate_options(_opts, _module), do: {:error, ["options must be a keyword list"]}

    defp validate_unique_options(opts, module) do
      schema = Keyword.get(opts, :schema)
      core_opts = opts |> Keyword.take(@core_option_keys) |> Keyword.put(:for, schema)

      core =
        case Policy.validate_options(core_opts, module) do
          {:ok, info} -> {:ok, %{info | enforces_binding: true}}
          {:error, errors} -> {:error, Enum.reject(errors, &(&1 =~ "`:for`"))}
        end

      errors =
        unknown_option_errors(opts) ++
          core_errors(core) ++
          schema_errors(schema) ++
          as_errors(Keyword.get(opts, :as)) ++
          tenant_field_errors(schema, Keyword.get(opts, :tenant)) ++
          null_tenant_errors(Keyword.get(opts, :null_tenant, false), Keyword.get(opts, :tenant)) ++
          repo_errors(Keyword.get(opts, :repo)) ++
          subject_id_errors(Keyword.get(opts, :subject_id, :id)) ++
          write_actions_errors(Keyword.get(opts, :write_actions, []), opts)

      finish_options(errors, core, opts)
    end

    defp finish_options([], {:ok, core}, opts) do
      schema = Keyword.fetch!(opts, :schema)
      [primary_key] = schema.__schema__(:primary_key)

      options = %{
        schema: schema,
        as: Keyword.fetch!(opts, :as),
        tenant: Keyword.get(opts, :tenant),
        null_tenant: Keyword.get(opts, :null_tenant, false),
        repo: Keyword.get(opts, :repo),
        subject_id: Keyword.get(opts, :subject_id, :id),
        write_actions: Keyword.get(opts, :write_actions, []),
        primary_key: primary_key,
        primary_key_type: schema.__schema__(:type, primary_key)
      }

      {:ok, core, options}
    end

    defp finish_options(errors, _core, _opts), do: {:error, errors}

    defp unknown_option_errors(opts) do
      case Keyword.keys(opts) -- option_keys() do
        [] -> []
        unknown -> ["unknown options: #{inspect(unknown)}"]
      end
    end

    defp core_errors({:ok, _info}), do: []
    defp core_errors({:error, errors}), do: errors

    defp schema_errors(schema) when is_atom(schema) and schema != nil do
      cond do
        not ecto_schema?(schema) ->
          ["`:schema` #{inspect(schema)} is not an Ecto schema"]

        not match?([_single], schema.__schema__(:primary_key)) ->
          ["`:schema` #{inspect(schema)} must have exactly one primary key field"]

        true ->
          []
      end
    end

    defp schema_errors(_schema), do: ["`:schema` (an Ecto schema module) is required"]

    @spec ecto_schema?(term) :: boolean
    def ecto_schema?(module) when is_atom(module) do
      match?({:module, _module}, Code.ensure_compiled(module)) and
        function_exported?(module, :__schema__, 1)
    end

    def ecto_schema?(_module), do: false

    defp as_errors(as) when is_atom(as) and as not in [nil, true, false], do: []
    defp as_errors(_as), do: ["`:as` (the name of the root binding, an atom) is required"]

    defp tenant_field_errors(_schema, nil), do: []

    defp tenant_field_errors(schema, tenant) when is_atom(tenant) do
      if ecto_schema?(schema) and tenant not in schema.__schema__(:fields),
        do: ["`:tenant` #{inspect(tenant)} is not a field of #{inspect(schema)}"],
        else: []
    end

    defp tenant_field_errors(_schema, _tenant), do: []

    defp null_tenant_errors(false, _tenant), do: []
    defp null_tenant_errors(true, nil), do: ["`:null_tenant` needs a `:tenant` field"]
    defp null_tenant_errors(true, _tenant), do: []
    defp null_tenant_errors(_value, _tenant), do: ["`:null_tenant` must be a boolean"]

    defp repo_errors(nil), do: []
    defp repo_errors(repo) when is_atom(repo), do: []
    defp repo_errors(_repo), do: ["`:repo` must be an Ecto repo module"]

    defp subject_id_errors(key) when is_atom(key) and key not in [nil, true, false], do: []
    defp subject_id_errors(_key), do: ["`:subject_id` must be the key of the subject's id"]

    defp write_actions_errors(writes, opts) when is_list(writes) do
      actions = Keyword.get(opts, :actions, [])

      case Enum.reject(writes, &(is_list(actions) and &1 in actions)) do
        [] ->
          []

        unknown ->
          ["`:write_actions` names actions that are not in `:actions`: #{inspect(unknown)}"]
      end
    end

    defp write_actions_errors(_writes, _opts),
      do: ["`:write_actions` must be a list of actions"]

    # Turns the recorded clauses into per-action plans. `scope_patterns` are the first
    # argument patterns of the hand-written `scope/4` clauses (`{:literal, action}` or
    # `:any`). Returns `{:ok, actions_map}` or `{:error, errors}`.
    @spec plan([map], map, map, [term]) :: {:ok, map} | {:error, [String.t()]}
    def plan(clauses, core, options, scope_patterns) do
      catalog = core.authorizer.__warden_catalog__()
      clause_errors = Enum.flat_map(clauses, &clause_errors(&1, core, options, catalog))
      action_errors = action_errors(clauses, core.actions, scope_patterns)

      case clause_errors ++ action_errors do
        [] -> {:ok, Map.new(core.actions, &{&1, action_plan(&1, clauses, options)})}
        errors -> {:error, errors}
      end
    end

    defp action_plan(action, clauses, options) do
      mine = Enum.filter(clauses, &(&1.action == action))

      if mine == [] do
        :scope
      else
        requires = for clause <- mine, clause.kind == :require, do: finish_clause(clause, options)
        allows = for clause <- mine, clause.kind == :allow, do: finish_clause(clause, options)
        {:clauses, requires, allows}
      end
    end

    # `if_nil:` is folded into its `through:` part, and literal values are cast to their
    # field types, so the stored plan compares like the database does.
    defp finish_clause(clause, options) do
      parts =
        for {key, _value} = part <- clause.parts,
            key != :if_nil,
            do: finish_part(part, clause.parts, options.schema)

      %{kind: clause.kind, action: clause.action, index: clause.index, parts: parts}
    end

    defp finish_part({:through, value}, parts, _schema) do
      {assoc, action} = assoc_action(value)
      if_nil = Keyword.get(parts, :if_nil, :deny)
      {:through, assoc, action, if_nil}
    end

    defp finish_part({:through_any, value}, _parts, _schema) do
      {assoc, action} = assoc_action(value)
      {:through_any, assoc, action}
    end

    defp finish_part({:rule, rule}, _parts, _schema), do: {:rule, tenant_from_arg(rule)}

    defp finish_part({:where, conditions}, _parts, schema) do
      cast = for {field, value} <- conditions, do: {field, cast!(schema, field, value)}
      {:where, cast}
    end

    defp finish_part({:through_type, value}, _parts, schema),
      do: {:through_type, through_type(value, schema)}

    defp finish_part({:grant, {link, row_key, grantee_key, opts}}, _parts, _schema),
      do: {:grant, link, row_key, grantee_key, Keyword.get(opts, :expires_at)}

    defp finish_part({:member_of, {link, row_key, actor_key}}, _parts, _schema),
      do: {:member_of, link, row_key, actor_key}

    defp finish_part({:within, {bounds_key, field}}, _parts, _schema),
      do: {:within, bounds_key, field}

    defp finish_part({key, value}, _parts, _schema), do: {key, value}

    defp cast!(_schema, _field, nil), do: nil

    defp cast!(schema, field, value) do
      {:ok, cast} = Ecto.Type.cast(schema.__schema__(:type, field), value)
      cast
    end

    defp assoc_action({assoc, action}), do: {assoc, action}
    defp assoc_action(assoc), do: {assoc, nil}

    defp through_type({type_field, id_field, policies}, schema) do
      targets =
        Map.new(policies, fn
          {type, {policy, action}} -> {cast!(schema, type_field, type), {policy, action}}
          {type, policy} -> {cast!(schema, type_field, type), {policy, nil}}
        end)

      {type_field, id_field, targets}
    end

    # A `rule:` clause is about the actor in the tenant being scoped, so `tenant_role/1`
    # (whose tenant is "the value's") reads the tenant from `args.tenant` instead.
    defp tenant_from_arg({:tenant_role, role, opts}) do
      case Keyword.get(opts, :tenant, :value) do
        :value -> {:tenant_role, role, Keyword.put(opts, :tenant, {:arg, [:tenant]})}
        _other -> {:tenant_role, role, opts}
      end
    end

    defp tenant_from_arg({tag, rules}) when tag in [:all, :any] and is_list(rules),
      do: {tag, Enum.map(rules, &tenant_from_arg/1)}

    defp tenant_from_arg(rule), do: rule

    defp action_errors(clauses, actions, scope_patterns) do
      clause_actions = clauses |> Enum.map(& &1.action) |> Enum.uniq()
      scope_any? = :any in scope_patterns
      scope_literals = for {:literal, action} <- scope_patterns, do: action

      unknown_scope =
        for action <- Enum.uniq(scope_literals), action not in actions do
          "scope/4 has a clause for #{inspect(action)}, which is not in `:actions`"
        end

      both =
        for action <- clause_actions,
            action in actions,
            scope_any? or action in scope_literals do
          """
          #{inspect(action)} has both a scope/4 clause and allow/requires clauses; \
          use one or the other per action\
          """
        end

      missing =
        for action <- actions,
            action not in clause_actions,
            not scope_any?,
            action not in scope_literals do
          "#{inspect(action)} has neither allow clauses nor a scope/4 clause"
        end

      no_allow =
        for action <- clause_actions,
            not Enum.any?(clauses, &(&1.action == action and &1.kind == :allow)) do
          """
          #{inspect(action)} has requires clauses but no allow clause, so it would never \
          allow anything\
          """
        end

      unknown_scope ++ both ++ missing ++ no_allow
    end

    defp clause_errors(clause, core, options, catalog) do
      where = "#{clause.kind} #{inspect(clause.action)} (line #{clause.line})"

      errors =
        action_clause_errors(clause, core) ++
          keys_errors(clause) ++
          Enum.flat_map(clause.parts, &part_errors(&1, clause, options, catalog))

      Enum.map(errors, &"#{where}: #{&1}")
    end

    defp action_clause_errors(clause, core) do
      if clause.action in core.actions,
        do: [],
        else: ["#{inspect(clause.action)} is not in `:actions` #{inspect(core.actions)}"]
    end

    defp keys_errors(clause) do
      keys = Keyword.keys(clause.parts)

      unknown_key_errors(keys) ++
        duplicate_key_errors(keys) ++ actor_key_errors(clause.kind, keys) ++ if_nil_errors(keys)
    end

    defp unknown_key_errors(keys) do
      case keys -- @clause_keys do
        [] -> []
        unknown -> ["unknown clause keys: #{inspect(unknown)} (known: #{inspect(@clause_keys)})"]
      end
    end

    defp duplicate_key_errors(keys) do
      case keys -- Enum.uniq(keys) do
        [] -> []
        duplicated -> ["clause keys given twice: #{inspect(Enum.uniq(duplicated))}"]
      end
    end

    defp actor_key_errors(_kind, []), do: ["a clause needs at least one condition"]

    defp actor_key_errors(:allow, keys) do
      if Enum.any?(keys, &(&1 in @actor_keys)) do
        []
      else
        message = """
        an allow clause needs a condition on the actor (#{inspect(@actor_keys)}); for rows \
        that every actor may see, say `rule: public()`\
        """

        [message]
      end
    end

    defp actor_key_errors(:require, _keys), do: []

    defp if_nil_errors(keys) do
      if :if_nil in keys and :through not in keys,
        do: ["`if_nil:` is an option of `through:`"],
        else: []
    end

    defp part_errors({:rule, rule}, _clause, _options, catalog) do
      validation =
        case Warden.Rule.validate(rule, catalog) do
          :ok -> []
          {:error, errors} -> Enum.map(errors, &"`rule:` #{&1}")
        end

      validation ++ rule_leaf_errors(rule)
    end

    defp part_errors({:where, conditions}, _clause, options, _catalog) do
      if Keyword.keyword?(conditions) and conditions != [] do
        Enum.flat_map(conditions, &where_errors(&1, options.schema))
      else
        ["`where:` must be a non-empty keyword list of field: value"]
      end
    end

    defp part_errors({:through, value}, _clause, options, _catalog) do
      with {:ok, assoc, _action} <- assoc_action_value(value, "through"),
           {:ok, association} <- association(options.schema, assoc, "through") do
        through_errors(association, options)
      else
        {:error, error} -> [error]
      end
    end

    defp part_errors({:through_any, value}, _clause, options, _catalog) do
      with {:ok, assoc, _action} <- assoc_action_value(value, "through_any"),
           {:ok, association} <- association(options.schema, assoc, "through_any") do
        through_any_errors(association, options)
      else
        {:error, error} -> [error]
      end
    end

    defp part_errors({:none, assoc}, _clause, options, _catalog) when is_atom(assoc) do
      case association(options.schema, assoc, "none") do
        {:ok, %mod{cardinality: :many}} when mod in [Has, ManyToMany] -> []
        {:ok, %Has{}} -> []
        {:ok, _other} -> ["`none: #{inspect(assoc)}` must be a has_many, has_one or many_to_many"]
        {:error, error} -> [error]
      end
    end

    defp part_errors({:none, other}, _clause, _options, _catalog),
      do: ["`none:` must be an association name, got: #{inspect(other)}"]

    defp part_errors({:actor_in, fields}, _clause, options, _catalog)
         when is_list(fields) and fields != [] do
      Enum.flat_map(fields, &field_errors(options.schema, &1, "actor_in"))
    end

    defp part_errors({:actor_in, other}, _clause, _options, _catalog),
      do: ["`actor_in:` must be a non-empty list of fields, got: #{inspect(other)}"]

    defp part_errors({:member_of, {schema, row_key, actor_key}}, _clause, _options, _catalog)
         when is_atom(row_key) and is_atom(actor_key) do
      link_errors(schema, [row_key, actor_key], "member_of")
    end

    defp part_errors({:member_of, other}, _clause, _options, _catalog),
      do: ["`member_of:` must be {schema, row_key, actor_key}, got: #{inspect(other)}"]

    defp part_errors({:grant, {schema, row_key, grantee_key, opts}}, _clause, _options, _catalog)
         when is_atom(row_key) and is_atom(grantee_key) and is_list(opts) do
      expires = Keyword.get(opts, :expires_at)

      opts_errors =
        case Keyword.keys(opts) -- [:expires_at] do
          [] -> []
          unknown -> ["`grant:` options: unknown #{inspect(unknown)} (known: [:expires_at])"]
        end

      fields =
        if expires == nil, do: [row_key, grantee_key], else: [row_key, grantee_key, expires]

      opts_errors ++ link_errors(schema, fields, "grant") ++ expires_errors(schema, expires)
    end

    defp part_errors({:grant, other}, _clause, _options, _catalog),
      do: ["`grant:` must be {schema, row_key, grantee_key, opts}, got: #{inspect(other)}"]

    defp part_errors(
           {:through_type, {type_field, id_field, policies}},
           _clause,
           options,
           _catalog
         )
         when is_map(policies) and map_size(policies) > 0 do
      field_errors(options.schema, type_field, "through_type") ++
        field_errors(options.schema, id_field, "through_type") ++
        Enum.flat_map(policies, &through_type_target_errors(&1, options.schema, type_field))
    end

    defp part_errors({:through_type, other}, _clause, _options, _catalog) do
      [
        "`through_type:` must be {type_field, id_field, %{type => policy}}, got: #{inspect(other)}"
      ]
    end

    defp part_errors({:within, {bounds_key, field}}, _clause, options, _catalog)
         when is_atom(bounds_key) do
      field_errors(options.schema, field, "within")
    end

    defp part_errors({:within, other}, _clause, _options, _catalog),
      do: ["`within:` must be {bounds_key, field}, got: #{inspect(other)}"]

    defp part_errors({:when, {:function, name}}, _clause, _options, _catalog) when is_atom(name),
      do: []

    defp part_errors({:if_nil, value}, _clause, options, _catalog) do
      cond do
        value not in @if_nil_values ->
          ["`if_nil:` must be one of #{inspect(@if_nil_values)}, got: #{inspect(value)}"]

        value == :tenant and options.tenant == nil ->
          ["`if_nil: :tenant` needs a policy with a `:tenant` field"]

        true ->
          []
      end
    end

    defp part_errors({_key, _value}, _clause, _options, _catalog), do: []

    # A `rule:` clause is about the actor only: `can/2` needs a value and `covered()` is
    # for GraphQL fields, and a tenant from an argument does not exist in a scope.
    defp rule_leaf_errors({tag, rules}) when tag in [:all, :any] and is_list(rules),
      do: Enum.flat_map(rules, &rule_leaf_errors/1)

    defp rule_leaf_errors({:can, _policy, _action, _opts}),
      do: ["`rule:` cannot use can/2,3; use `through:` for a parent's policy"]

    defp rule_leaf_errors(:covered), do: ["`rule:` cannot use covered()"]

    defp rule_leaf_errors({:tenant_role, _role, opts}) when is_list(opts) do
      case Keyword.get(opts, :tenant, :value) do
        :value -> []
        _other -> ["`rule:` tenant_role/2 takes the tenant being scoped; drop `tenant:`"]
      end
    end

    defp rule_leaf_errors(_rule), do: []

    defp where_errors({field, value}, schema) do
      with [] <- field_errors(schema, field, "where") do
        cast_errors(schema, field, value, "where")
      end
    end

    defp cast_errors(_schema, _field, nil, _key), do: []

    defp cast_errors(schema, field, value, key) do
      type = schema.__schema__(:type, field)

      cond do
        is_list(value) or (is_map(value) and not is_struct(value)) ->
          ["`#{key}:` #{inspect(field)} must be compared with a single literal value"]

        match?({:ok, _cast}, Ecto.Type.cast(type, value)) ->
          []

        true ->
          ["`#{key}:` #{inspect(value)} is not a valid #{inspect(type)} for #{inspect(field)}"]
      end
    end

    defp field_errors(schema, field, key) when is_atom(field) do
      if field in schema.__schema__(:fields),
        do: [],
        else: ["`#{key}:` #{inspect(field)} is not a field of #{inspect(schema)}"]
    end

    defp field_errors(_schema, field, key),
      do: ["`#{key}:` expects field names, got: #{inspect(field)}"]

    defp assoc_action_value({assoc, action}, _key) when is_atom(assoc) and is_atom(action),
      do: {:ok, assoc, action}

    defp assoc_action_value(assoc, _key) when is_atom(assoc), do: {:ok, assoc, nil}

    defp assoc_action_value(other, key),
      do:
        {:error,
         "`#{key}:` must be an association or {association, action}, got: #{inspect(other)}"}

    # An association with a `where:` (or `join_where:`) filter would be scoped without
    # it, which admits rows the association leaves out; it is refused.
    defp association(schema, assoc, key) do
      case schema.__schema__(:association, assoc) do
        nil ->
          {:error, "`#{key}:` #{inspect(assoc)} is not an association of #{inspect(schema)}"}

        association ->
          if Map.get(association, :where, []) == [] and
               Map.get(association, :join_where, []) == [],
             do: {:ok, association},
             else:
               {:error, "`#{key}: #{inspect(assoc)}` has a `where:` filter; use a `when:` clause"}
      end
    end

    # A `through` to the schema itself is a cycle: the parent's policy is this policy.
    defp through_errors(%BelongsTo{} = association, options) do
      if association.related == options.schema,
        do: ["`through: #{inspect(association.field)}` is a cycle: it leads back to this policy"],
        else: []
    end

    defp through_errors(association, _options),
      do: ["`through: #{inspect(association.field)}` must be a belongs_to association"]

    defp through_any_errors(%mod{cardinality: :many} = association, options)
         when mod in [Has, ManyToMany] do
      if association.related == options.schema,
        do: [
          "`through_any: #{inspect(association.field)}` is a cycle: it leads back to this policy"
        ],
        else: []
    end

    defp through_any_errors(association, _options) do
      ["`through_any: #{inspect(association.field)}` must be a has_many or many_to_many"]
    end

    defp link_errors(schema, fields, key) when is_binary(schema) do
      Enum.flat_map(fields, fn
        field when is_atom(field) -> []
        field -> ["`#{key}:` expects field names, got: #{inspect(field)}"]
      end)
    end

    defp link_errors(schema, fields, key) when is_atom(schema) do
      if ecto_schema?(schema),
        do: Enum.flat_map(fields, &field_errors(schema, &1, key)),
        else: ["`#{key}:` #{inspect(schema)} is not an Ecto schema (or a table name)"]
    end

    defp link_errors(schema, _fields, key),
      do: ["`#{key}:` expects an Ecto schema or a table name, got: #{inspect(schema)}"]

    defp expires_errors(_schema, nil), do: []
    # The current time must be sent in the column's own type (a naive timestamp compared
    # with a `timestamptz` shifts by the session's time zone), so it needs a schema.
    defp expires_errors(schema, _expires) when is_binary(schema) do
      [
        "`grant:` with `expires_at:` needs a schema, not the table name #{inspect(schema)}, so the column's type is known"
      ]
    end

    defp expires_errors(schema, expires) do
      type = if ecto_schema?(schema), do: schema.__schema__(:type, expires)

      if type in [nil, :utc_datetime, :utc_datetime_usec, :naive_datetime, :naive_datetime_usec],
        do: [],
        else: ["`grant:` `expires_at:` #{inspect(expires)} must be a datetime field"]
    end

    defp through_type_target_errors({type, target}, schema, type_field) do
      cast =
        if is_atom(type_field),
          do: cast_errors(schema, type_field, type, "through_type"),
          else: []

      target_errors =
        case target do
          {policy, action} when is_atom(policy) and is_atom(action) ->
            []

          policy when is_atom(policy) ->
            []

          other ->
            ["`through_type:` #{inspect(type)} must map to a policy, got: #{inspect(other)}"]
        end

      cast ++ target_errors
    end

    # True when Elixir equality on a value of this field type is the database's
    # equality, so a loaded struct can be compared without a query.
    @spec exact_type?(term) :: boolean
    def exact_type?(type) when type in @exact_types, do: true
    def exact_type?({:parameterized, {Ecto.Enum, _params}}), do: true
    def exact_type?({:parameterized, Ecto.Enum, _params}), do: true
    def exact_type?(_type), do: false

    # The first-argument patterns of the hand-written `scope/4` clauses.
    @spec scope_patterns(module) :: [{:literal, atom} | :any]
    def scope_patterns(module) do
      if Module.defines?(module, {:scope, 4}) do
        {:v1, _kind, _meta, clauses} = Module.get_definition(module, {:scope, 4})
        Enum.map(clauses, fn {_meta, [action | _rest], _guards, _body} -> pattern(action) end)
      else
        []
      end
    end

    defp pattern(action) when is_atom(action), do: {:literal, action}
    defp pattern(_pattern), do: :any
  end
end
