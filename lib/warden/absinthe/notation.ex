# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Notation do
    @moduledoc """
    Schema notation for Warden rules.

    `use Warden.Absinthe` imports this module in a schema. In a type module that you pull in
    with `import_types`, add `use Warden.Absinthe.Notation` after `use Absinthe.Schema.Notation`.

    The rule builders from `Warden.Rule` are imported too.

      * `authorize rule` - inside `field` (an object field or an input object field),
        `object`, `interface` or `union`.
      * `authorize rule, on_deny: :null | {:replace, value} | :error` - inside an object
        `field`: what a denial of this field's rule becomes, for this field only.
      * `authorize_args name: rule, ...` - inside an object `field`.
      * `list_policy :null_item | :filter | :fail_list` - inside an object `field`.
      * `redact_with FieldsModule` - inside `object`: the field policy (`Warden.Fields`)
        applied to the object's values.
      * `warden_schema Schema` - inside `object`: the Ecto schema (or struct) of the
        object's values, for `require_can_for:`.

    Rules are evaluated when the schema compiles, so they must be built from literals,
    module attributes or compile-time expressions. They are stored in the schema `meta`
    under `:warden_rule`, `:warden_args` and `:warden_list_policy`.
    """

    alias Warden.Absinthe.Rules

    @doc false
    defmacro __using__(_opts) do
      quote do
        import Warden.Rule,
          only: [
            public: 0,
            authenticated: 0,
            deny: 0,
            role: 1,
            any_role: 1,
            permission: 1,
            all_permissions: 1,
            any_permission: 1,
            check: 1,
            check: 2,
            all_of: 1,
            any_of: 1,
            covered: 0,
            tenant_role: 1,
            tenant_role: 2,
            kind: 1,
            credential_scope: 1,
            session: 0,
            can: 2,
            can: 3
          ]

        import Warden.Absinthe.Notation,
          only: [
            authorize: 1,
            authorize: 2,
            authorize_args: 1,
            list_policy: 1,
            redact_with: 1,
            warden_schema: 1
          ]
      end
    end

    @doc """
    Attaches a rule to the enclosing field, input field, object, interface or union.

    On an object field it is a field rule: it runs before the resolver. On an input object
    field it is an input-field rule: it applies when a client sends a non-default value for
    that field. On an object, interface or union it is an object rule: values of that type
    that fail it become `null`.

    One `authorize` per definition; combine rules with `all_of/1` or `any_of/1`.

    `covered()` marks a field that its object type's rule guards; it is accepted only on
    fields of an object type (or interface) that has an object rule.
    """
    defmacro authorize(rule) do
      env = __CALLER__
      scope = current_scope(env, :authorize, [:field, :object, :interface, :union])
      rule = eval!(rule, env, "authorize")
      validate_rule!(env, rule)
      record!(env, scope, :warden_rule, rule)
    end

    @doc """
    Attaches a field rule with its own denial result, `on_deny:`:

      * `:error` (default) - the denial goes through the authorizer's `deny/1`;
      * `:null` - the field becomes `null` without an error (not allowed on a non-null
        field, which fails compilation);
      * `{:replace, value}` - the field resolves to `value`; object rules still apply to it.

    Only for object fields. `on_deny:` applies to a denial of the field rule itself, not to
    argument or object rules.
    """
    defmacro authorize(rule, opts) do
      env = __CALLER__
      scope = current_scope(env, :authorize, [:field])
      rule = eval!(rule, env, "authorize")
      opts = eval!(opts, env, "authorize")
      validate_rule!(env, rule)

      on_deny =
        case opts do
          [on_deny: on_deny] -> on_deny
          _other -> compile_error!(env, "`authorize rule, opts` only takes `on_deny:`")
        end

      if not Rules.valid_on_deny?(on_deny) do
        compile_error!(env, """
        `on_deny:` must be :null, {:replace, value} or :error, got: #{inspect(on_deny)}\
        """)
      end

      record!(env, scope, :warden_rule, rule)
      record!(env, scope, :warden_on_deny, on_deny)
    end

    defp validate_rule!(env, rule) do
      case Warden.Rule.validate(rule) do
        :ok ->
          :ok

        {:error, errors} ->
          compile_error!(env, "invalid rule in `authorize`: " <> Enum.join(errors, "; "))
      end
    end

    @doc """
    Attaches argument rules to the enclosing field: `authorize_args include_deleted: role(:admin)`.

    An argument rule applies when the effective argument value (after variables and
    defaults) differs from the schema default. A `null` sent for an argument whose default
    is not `null` counts as different.
    """
    defmacro authorize_args(rules) do
      env = __CALLER__
      scope = current_scope(env, :authorize_args, [:field])
      rules = eval!(rules, env, "authorize_args")

      unless Keyword.keyword?(rules) and rules != [] do
        compile_error!(env, "`authorize_args` expects a non-empty keyword list of arg: rule")
      end

      Enum.each(rules, fn {arg, rule} ->
        case Warden.Rule.validate(rule) do
          :ok ->
            :ok

          {:error, errors} ->
            compile_error!(
              env,
              "invalid rule for argument #{inspect(arg)} in `authorize_args`: " <>
                Enum.join(errors, "; ")
            )
        end
      end)

      dupes = Keyword.keys(rules) -- Enum.uniq(Keyword.keys(rules))

      if dupes != [] do
        compile_error!(env, "`authorize_args` names #{inspect(dupes)} more than once")
      end

      record!(env, scope, :warden_args, Map.new(rules))
    end

    @doc """
    Sets the list policy for the enclosing field: what happens to list items that an
    object rule denies. See the README.
    """
    defmacro list_policy(policy) do
      env = __CALLER__
      scope = current_scope(env, :list_policy, [:field])
      policy = eval!(policy, env, "list_policy")

      unless policy in Rules.list_policies() do
        compile_error!(
          env,
          "`list_policy` must be one of #{inspect(Rules.list_policies())}, got: #{inspect(policy)}"
        )
      end

      record!(env, scope, :warden_list_policy, policy)
    end

    @doc """
    Applies a field policy (a `Warden.Fields` module) to the values of the enclosing
    object type. After the object rule passes and before any child field resolves, Warden
    replaces the value with `Warden.redact/2` of it, so default and custom resolvers of the
    child fields read the redacted struct. It runs per list item (one decision per rule and
    list), behind interfaces and unions, on Dataloader, `Async` and `Batch` values, and on
    every subscription publish.

    Fails compilation when the module is not a field policy, belongs to another
    authorizer, or redacts another struct than the one the object type's `can/2` policy
    is about, and when it redacts a field with `with: nil` that the object type declares
    non-null.

    A value of another type than the policy's struct raises `Warden.PolicyError`.
    """
    defmacro redact_with(module) do
      env = __CALLER__
      scope = current_scope(env, :redact_with, [:object])
      module = eval!(module, env, "redact_with")

      if not fields_module?(module) do
        compile_error!(env, """
        `redact_with` needs a field policy (a module that does `use Warden.Fields`), got: \
        #{inspect(module)}\
        """)
      end

      record!(env, scope, :warden_redact_with, module)
    end

    @doc """
    Links the enclosing object type to the schema (or struct module) of its values:
    `warden_schema MyApp.Issues.Issue`. With `use Warden.Absinthe, strict_mode: :all,
    require_can_for: [MyApp.Issues.Issue]`, an object type linked to a listed schema
    whose object rule has no `can/2` for that schema's policy fails compilation.
    """
    defmacro warden_schema(schema) do
      env = __CALLER__
      scope = current_scope(env, :warden_schema, [:object])
      schema = eval!(schema, env, "warden_schema")

      if not (is_atom(schema) and schema not in [nil, true, false]) do
        compile_error!(env, "`warden_schema` needs a module, got: #{inspect(schema)}")
      end

      record!(env, scope, :warden_schema, schema)
    end

    defp fields_module?(module) do
      is_atom(module) and match?({:module, _module}, Code.ensure_compiled(module)) and
        function_exported?(module, :__warden_fields__, 1)
    end

    ## Helpers

    defp eval!(ast, env, macro) do
      {value, _} = Code.eval_quoted(ast, [], env)
      value
    rescue
      e ->
        compile_error!(
          env,
          "could not evaluate the argument of `#{macro}` at compile time: " <>
            Exception.message(e)
        )
    end

    defp current_scope(env, macro, allowed) do
      stack = Module.get_attribute(env.module, :absinthe_scope_stack)

      case stack do
        [scope | _] when is_list(stack) ->
          if scope in allowed do
            scope
          else
            compile_error!(
              env,
              "`#{macro}` must be used inside #{Enum.map_join(allowed, ", ", &"`#{&1}`")}, " <>
                "not inside `#{scope}`"
            )
          end

        _ ->
          compile_error!(env, "`#{macro}` must be used inside an Absinthe schema or type module")
      end
    end

    defp record!(env, _scope, key, value) do
      owner = current_owner_ref(env.module)
      seen = Module.get_attribute(env.module, :__warden_recorded__) || MapSet.new()

      if owner != nil and MapSet.member?(seen, {owner, key}) do
        compile_error!(
          env,
          "#{macro_name(key)} is declared twice for the same definition; " <>
            "use one call (combine rules with all_of/1 or any_of/1)"
        )
      end

      Module.put_attribute(env.module, :__warden_recorded__, MapSet.put(seen, {owner, key}))

      # Stored directly (not through `meta/1`) so the rule term is not treated as AST.
      Absinthe.Schema.Notation.put_attr(env.module, {:__private__, [{:meta, [{key, value}]}]})

      :ok
    end

    defp macro_name(:warden_rule), do: "`authorize`"
    defp macro_name(:warden_args), do: "`authorize_args`"
    defp macro_name(:warden_list_policy), do: "`list_policy`"
    defp macro_name(:warden_on_deny), do: "`on_deny:`"
    defp macro_name(:warden_redact_with), do: "`redact_with`"
    defp macro_name(:warden_schema), do: "`warden_schema`"

    # Finds the reference of the definition that is currently open, by walking the
    # recorded blueprint attributes backwards and balancing `:close` markers.
    defp current_owner_ref(module) do
      module
      |> Module.get_attribute(:absinthe_blueprint)
      |> List.wrap()
      |> find_owner(0)
    end

    defp find_owner([], _depth), do: nil
    defp find_owner([{_ref, :close} | rest], depth), do: find_owner(rest, depth + 1)

    defp find_owner([{ref, %struct{}} | rest], depth) do
      if scoped?(struct) do
        if depth == 0, do: ref, else: find_owner(rest, depth - 1)
      else
        find_owner(rest, depth)
      end
    end

    defp find_owner([_ | rest], depth), do: find_owner(rest, depth)

    defp scoped?(struct) do
      struct in [
        Absinthe.Blueprint.Schema.ObjectTypeDefinition,
        Absinthe.Blueprint.Schema.FieldDefinition,
        Absinthe.Blueprint.Schema.ScalarTypeDefinition,
        Absinthe.Blueprint.Schema.EnumTypeDefinition,
        Absinthe.Blueprint.Schema.EnumValueDefinition,
        Absinthe.Blueprint.Schema.InputObjectTypeDefinition,
        Absinthe.Blueprint.Schema.InputValueDefinition,
        Absinthe.Blueprint.Schema.UnionTypeDefinition,
        Absinthe.Blueprint.Schema.InterfaceTypeDefinition,
        Absinthe.Blueprint.Schema.DirectiveDefinition,
        Absinthe.Blueprint.Schema.SchemaDefinition,
        Absinthe.Blueprint.Schema.TypeExtensionDefinition
      ]
    end

    @spec compile_error!(Macro.Env.t(), String.t()) :: no_return()
    defp compile_error!(env, message) do
      raise CompileError, file: env.file, line: env.line, description: message
    end
  end
end
