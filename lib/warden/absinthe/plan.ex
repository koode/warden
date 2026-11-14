# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Plan do
    @moduledoc false
    # Computes, from the schema's types and the Warden configuration, which Warden
    # middleware every field needs. The same function runs in the schema pipeline (to
    # attach the middleware) and after compilation (to verify the compiled schema), so the
    # two can be compared exactly.

    alias Absinthe.Type
    alias Warden.Absinthe.Rules
    alias Warden.Fields.Redactor
    alias Warden.Rule

    @root_types [:query, :mutation, :subscription]
    # GraphQL names of the fields Absinthe's introspection adds. Matched by name, never by
    # identifier prefix: a user field `:__internal` named "internal" is an ordinary field.
    @introspection_fields ["__typename", "__schema", "__type"]
    @introspection_schema_fields ["__schema", "__type"]

    defstruct fields: %{}, subscriptions: %{}, object_rules: %{}, errors: []

    @type t :: %__MODULE__{}

    def root_types, do: @root_types

    @doc """
    Builds the plan. `types` maps identifiers to `Absinthe.Type` structs. Returns the plan;
    `plan.errors` lists every problem found (catalog, placement, strict mode).
    """
    def build(types, config) do
      catalog = config.catalog
      object_rules = object_rules(types, config)
      redactors = redactors(types)

      errors =
        validate_meta(types, catalog) ++
          covered_errors(types, object_rules) ++
          redact_errors(types, config) ++
          missing_redaction_errors(types, config) ++ argument_leaf_errors(types)

      inputs = input_plans(types)

      # For abstract types the concrete type comes from user code (`resolve_type`), which
      # may return a type outside the declared members, so every object rule is in reach
      # of an abstract field. Built once here, not per field.
      object_type_rules =
        for {ident, rule} <- object_rules,
            match?(%Type.Object{}, Map.get(types, ident)),
            into: %{},
            do: {ident, rule}

      {fields, subs} =
        for {_, %Type.Object{} = object} <- types,
            not introspection_type?(object),
            {_, field} <- object.fields,
            reduce: {%{}, %{}} do
          {fields, subs} ->
            pre = pre_spec(object, field, types, {object_rules, redactors}, inputs, config)
            rules = {object_rules, object_type_rules, redactors}
            post = post_spec(object, field, types, rules, config)

            fields =
              if pre || post,
                do: Map.put(fields, {object.identifier, field.identifier}, {pre, post}),
                else: fields

            subs =
              if object.identifier == :subscription and not introspection_field?(field),
                do:
                  Map.put(
                    subs,
                    field.identifier,
                    subscribe_spec(pre, field, types, object_rules, config)
                  ),
                else: subs

            {fields, subs}
        end

      errors = errors ++ strict_errors(types, config)

      %__MODULE__{
        fields: fields,
        subscriptions: subs,
        object_rules: object_rules,
        errors: errors
      }
    end

    ## Rule lookup

    defp meta(node, key), do: Type.meta(node, key)

    defp introspection_type?(%{name: "__" <> _}), do: true
    defp introspection_type?(_), do: false

    defp introspection_field?(%{name: name}), do: name in @introspection_fields

    # The effective object rule of every type that has one.
    #
    # Object types: own rule (or `default_object_rule` for non-root, non-introspection
    # objects without one) AND the object rule of every interface the object implements.
    # Interfaces and unions: their own rule.
    defp object_rules(types, config) do
      Enum.reduce(types, %{}, fn {ident, type}, acc ->
        case object_rule(ident, type, types, config) do
          nil -> acc
          rule -> Map.put(acc, ident, rule)
        end
      end)
    end

    defp object_rule(ident, %Type.Object{} = object, types, config) do
      Rules.conjoin([
        own_object_rule(ident, object, config) | interface_object_rules(object, types)
      ])
    end

    defp object_rule(_ident, %Type.Interface{} = interface, _types, _config),
      do: Rules.conjoin([meta(interface, :warden_rule)])

    defp object_rule(_ident, %Type.Union{} = union, _types, _config),
      do: Rules.conjoin([meta(union, :warden_rule)])

    defp object_rule(_ident, _type, _types, _config), do: nil

    # The object's own rule, or `default_object_rule` for a non-root, non-introspection
    # object without one.
    defp own_object_rule(ident, object, config) do
      own = meta(object, :warden_rule)

      if own == nil and not introspection_type?(object) and ident not in @root_types,
        do: config.default_object_rule,
        else: own
    end

    defp interface_object_rules(object, types) do
      object.interfaces
      |> List.wrap()
      |> Enum.map(fn iface ->
        case Map.get(types, iface) do
          nil -> nil
          interface -> meta(interface, :warden_rule)
        end
      end)
    end

    ## Pre

    defp pre_spec(object, field, types, {object_rules, redactors}, inputs, config) do
      root? = object.identifier in @root_types
      ctx = %{types: types, object_rules: object_rules, inputs: inputs, config: config}

      case pre_checks(object, field, root?, ctx) do
        [] ->
          nil

        checks ->
          %{authorizer: config.authorizer, root: root?, checks: checks}
          |> with_on_deny(field)
          |> with_admissible(checks, redactors, config)
      end
    end

    # The post middleware admits values of a type whose object rule is batched or that
    # redacts (`Warden.Absinthe.Decide`); only the fields of such a type look admissions
    # up, so every other field pays nothing for them.
    defp with_admissible(spec, [{:object, type, rule} | _rest], redactors, config) do
      if admissible?(type, rule, redactors, config),
        do: Map.put(spec, :admissible, true),
        else: spec
    end

    defp with_admissible(spec, _checks, _redactors, _config), do: spec

    defp admissible?(type, rule, redactors, config),
      do: Map.has_key?(redactors, type) or Warden.Evaluator.batched?(rule, config.catalog)

    defp pre_checks(object, field, root?, ctx) do
      cond do
        # Absinthe adds `__schema` and `__type` to every object named like a query root,
        # so the introspection rule guards them wherever they appear. A root object rule
        # applies too.
        field.name in @introspection_schema_fields ->
          parent_check(object, ctx) ++ introspection_check(ctx.config)

        # `__typename` of a root type is guarded by the root's object rule.
        introspection_field?(field) ->
          if root?, do: parent_check(object, ctx), else: []

        true ->
          parent_check(object, ctx) ++
            field_check(object, field, ctx) ++ args_check(object, field, ctx)
      end
    end

    # `authorize rule, on_deny: ...` on the field itself.
    defp with_on_deny(spec, field) do
      case meta(field, :warden_on_deny) do
        nil -> spec
        on_deny -> Map.put(spec, :on_deny, on_deny)
      end
    end

    defp parent_check(object, ctx) do
      case Map.get(ctx.object_rules, object.identifier) do
        nil -> []
        rule -> [{:object, object.identifier, rule}]
      end
    end

    defp introspection_check(%{introspection: :public}), do: []
    defp introspection_check(%{introspection: rule}), do: [{:introspection, rule}]

    defp field_check(object, field, ctx) do
      case effective_field_rule(object, field, ctx.types) do
        nil -> []
        rule -> [{:field, rule}]
      end
    end

    defp args_check(object, field, ctx) do
      case arg_plan(object, field, ctx.types, ctx.inputs) do
        nil -> []
        plan -> [{:args, plan}]
      end
    end

    def effective_field_rule(object, field, types) do
      interface_rules =
        for iface_ident <- List.wrap(object.interfaces),
            %{fields: ifields} <- [Map.get(types, iface_ident)],
            ifield = Map.get(ifields, field.identifier),
            ifield != nil do
          meta(ifield, :warden_rule)
        end

      Rules.conjoin([meta(field, :warden_rule) | interface_rules])
    end

    defp effective_arg_rules(object, field, types) do
      interface_args =
        for iface_ident <- List.wrap(object.interfaces),
            %{fields: ifields} <- [Map.get(types, iface_ident)],
            ifield = Map.get(ifields, field.identifier),
            ifield != nil do
          meta(ifield, :warden_args) || %{}
        end

      # A rule can also sit on the argument itself (`Warden.Absinthe.Hydrate.meta(rule: ...)` on an
      # argument node).
      on_args =
        for f <- [field | interface_fields(object, field, types)],
            {ident, arg} <- f.args || %{},
            rule = meta(arg, :warden_rule),
            rule != nil,
            do: %{ident => rule}

      Enum.reduce(interface_args ++ on_args, meta(field, :warden_args) || %{}, fn rules, acc ->
        Map.merge(acc, rules, fn _k, a, b -> Rules.conjoin([a, b]) end)
      end)
      |> Enum.reject(fn {_, rule} -> rule in [nil, :public] end)
      |> Map.new()
    end

    # Argument plan: a sorted list of {arg_ident, rule | nil, defaults, input_specs} plus
    # the input-object plans it references.
    #
    # The arguments are the union of the object field's arguments and those of the
    # same-named field on every interface the object implements: a client selecting
    # through an interface is validated against the interface's arguments, and the
    # concrete field then runs with them. `defaults` holds every declared default, or is
    # empty when any declaration has none; `input_specs` holds the input type walk of every
    # declaration.
    defp arg_plan(object, field, types, inputs) do
      arg_rules = effective_arg_rules(object, field, types)

      declarations =
        [field | interface_fields(object, field, types)]
        |> Enum.flat_map(fn f -> Map.to_list(f.args || %{}) end)
        |> Enum.group_by(fn {ident, _} -> ident end, fn {_, arg} -> arg end)

      args =
        declarations
        |> Enum.sort_by(fn {ident, _} -> ident end)
        |> Enum.flat_map(fn {ident, decls} ->
          rule = Map.get(arg_rules, ident)

          specs =
            decls
            |> Enum.map(&input_spec(&1.type, types, inputs))
            |> Enum.reject(&is_nil/1)
            |> Enum.uniq()

          # If any declaration has no default, a client value is a choice the client made
          # (the field without a default runs with it), so every present value is
          # restricted: `defaults` is empty. Otherwise a value is restricted when it differs
          # from any declared default.
          defaults =
            if Enum.any?(decls, &is_nil(&1.default_value)),
              do: [],
              else: decls |> Enum.map(& &1.default_value) |> Enum.uniq()

          if rule == nil and specs == [],
            do: [],
            else: [{ident, rule, defaults, specs}]
        end)

      case args do
        [] ->
          nil

        args ->
          referenced = referenced_inputs(args, inputs)
          %{args: args, inputs: Map.take(inputs, referenced)}
      end
    end

    defp interface_fields(object, field, types) do
      for iface_ident <- List.wrap(object.interfaces),
          %{fields: ifields} <- [Map.get(types, iface_ident)],
          ifield = Map.get(ifields, field.identifier),
          ifield != nil,
          do: ifield
    end

    defp input_spec(%Type.NonNull{of_type: t}, types, inputs) do
      case input_spec(t, types, inputs) do
        nil -> nil
        spec -> {:non_null, spec}
      end
    end

    defp input_spec(%Type.List{of_type: t}, types, inputs) do
      case input_spec(t, types, inputs) do
        nil -> nil
        spec -> {:list, spec}
      end
    end

    defp input_spec(ident, _types, inputs) when is_atom(ident) do
      if Map.has_key?(inputs, ident), do: {:input, ident}, else: nil
    end

    defp input_spec(_, _, _), do: nil

    defp referenced_inputs(args, inputs) do
      args
      |> Enum.flat_map(fn {_, _, _, specs} -> Enum.flat_map(specs, &spec_inputs/1) end)
      |> close_over(inputs, %{})
      |> Map.keys()
      |> Enum.sort()
    end

    # The visited set is a plain map; see `reachable/3` in Warden.Authorizer.
    defp close_over([], _inputs, seen), do: seen

    defp close_over([ident | rest], inputs, seen) do
      if Map.has_key?(seen, ident) do
        close_over(rest, inputs, seen)
      else
        nested =
          inputs
          |> Map.fetch!(ident)
          |> Enum.flat_map(fn {_, _, _, specs} -> Enum.flat_map(specs, &spec_inputs/1) end)

        close_over(nested ++ rest, inputs, Map.put(seen, ident, true))
      end
    end

    defp spec_inputs(nil), do: []
    defp spec_inputs({:input, ident}), do: [ident]
    defp spec_inputs({_, spec}), do: spec_inputs(spec)

    # Plans for every input object that has an input-field rule somewhere below it.
    defp input_plans(types) do
      input_objects = for {ident, %Type.InputObject{} = t} <- types, into: %{}, do: {ident, t}

      with_rules =
        fixpoint(
          input_objects
          |> Enum.filter(fn {_, t} ->
            Enum.any?(t.fields, fn {_, f} -> meta(f, :warden_rule) not in [nil, :public] end)
          end)
          |> MapSet.new(fn {ident, _} -> ident end),
          input_objects
        )

      Map.new(with_rules, fn ident ->
        fields =
          input_objects
          |> Map.fetch!(ident)
          |> Map.fetch!(:fields)
          |> Enum.sort_by(fn {fident, _} -> fident end)
          |> Enum.flat_map(&input_field_plan(&1, with_rules))

        {ident, fields}
      end)
    end

    defp input_field_plan({fident, field}, with_rules) do
      rule = if meta(field, :warden_rule) == :public, do: nil, else: meta(field, :warden_rule)
      specs = List.wrap(input_ref_spec(field.type, with_rules))
      defaults = if field.default_value == nil, do: [], else: [field.default_value]

      if rule == nil and specs == [],
        do: [],
        else: [{fident, rule, defaults, specs}]
    end

    defp fixpoint(set, input_objects) do
      next =
        input_objects
        |> Enum.filter(fn {ident, t} ->
          not MapSet.member?(set, ident) and
            Enum.any?(t.fields, fn {_, f} -> MapSet.member?(set, Type.unwrap(f.type)) end)
        end)
        |> MapSet.new(fn {ident, _} -> ident end)

      if MapSet.size(next) == 0, do: set, else: fixpoint(MapSet.union(set, next), input_objects)
    end

    defp input_ref_spec(%Type.NonNull{of_type: t}, set) do
      case input_ref_spec(t, set) do
        nil -> nil
        spec -> {:non_null, spec}
      end
    end

    defp input_ref_spec(%Type.List{of_type: t}, set) do
      case input_ref_spec(t, set) do
        nil -> nil
        spec -> {:list, spec}
      end
    end

    defp input_ref_spec(ident, set) when is_atom(ident) do
      if MapSet.member?(set, ident), do: {:input, ident}, else: nil
    end

    defp input_ref_spec(_, _), do: nil

    ## Post

    defp post_spec(object, field, types, rules, config) do
      {object_rules, object_type_rules, redactors} = rules

      if introspection_field?(field) do
        nil
      else
        named = Type.unwrap(field.type)
        shape = shape(field.type)

        {abstract_rule, concrete_rules, abstract_kind} =
          return_rules(Map.get(types, named), named, object_rules, object_type_rules)

        # Like object rules, any object type may stand behind an abstract type.
        field_redactors =
          if abstract_kind == nil, do: Map.take(redactors, [named]), else: redactors

        if abstract_rule == nil and map_size(concrete_rules) == 0 and
             map_size(field_redactors) == 0 do
          nil
        else
          spec = %{
            authorizer: config.authorizer,
            shape: shape,
            named: named,
            abstract: abstract_kind,
            abstract_rule: abstract_rule,
            rules: concrete_rules,
            list_policy: list_policy(object, field, types, config)
          }

          spec
          |> with_redactors(field_redactors)
          |> with_across_parents(config)
        end
      end
    end

    # {abstract_rule, concrete_rules, abstract_kind} for a field's return type.
    defp return_rules(%Type.Object{}, named, object_rules, _object_type_rules),
      do: {nil, Map.take(object_rules, [named]), nil}

    defp return_rules(%Type.Interface{}, named, object_rules, object_type_rules),
      do: {Map.get(object_rules, named), object_type_rules, :interface}

    defp return_rules(%Type.Union{}, named, object_rules, object_type_rules),
      do: {Map.get(object_rules, named), object_type_rules, :union}

    defp return_rules(_type, _named, _object_rules, _object_type_rules), do: {nil, %{}, nil}

    # Cross-parent batching: the object rule of a single object (not a list, not an
    # abstract type) is deferred through `Absinthe.Middleware.Batch`, so the values of
    # every parent at one level are decided together.
    #
    #   * `:auto` (default): for rules with a leaf that gains from a batch (a check with
    #     `batch: true`, or `can/2` over a policy with `allowed_many/4` or an Ecto
    #     policy), when the schema has the Batch plugin;
    #   * `true`: for every rule with a batched leaf (the verifier requires the plugin);
    #   * `false`: never.
    defp with_across_parents(%{abstract: nil, shape: shape} = spec, config)
         when shape in [:named, {:non_null, :named}] do
      rule = Map.get(spec.rules, spec.named)

      if across_parents?(rule, config),
        do: Map.put(spec, :across_parents, true),
        else: spec
    end

    defp with_across_parents(spec, _config), do: spec

    defp across_parents?(rule, %{batch_across_parents: true} = config),
      do: Warden.Evaluator.batched?(rule, config.catalog)

    defp across_parents?(rule, %{batch_across_parents: :auto} = config),
      do: Map.get(config, :batch_plugin?, false) and batch_gain?(rule, config.catalog)

    defp across_parents?(_rule, _config), do: false

    defp batch_gain?({tag, rules}, catalog) when tag in [:all, :any] and is_list(rules),
      do: Enum.any?(rules, &batch_gain?(&1, catalog))

    defp batch_gain?({:check, _name, _opts} = leaf, catalog),
      do: Warden.Evaluator.batched?(leaf, catalog)

    defp batch_gain?({:can, policy, _action, opts}, _catalog) when is_list(opts),
      do: not Keyword.has_key?(opts, :arg) and many_policy?(policy)

    defp batch_gain?(_rule, _catalog), do: false

    # A policy that answers a list at once: `allowed_many/4` or an Ecto policy.
    defp many_policy?(policy) do
      Code.ensure_loaded?(policy) and
        (function_exported?(policy, :allowed_many, 4) or
           function_exported?(policy, :__warden_ecto__, 1))
    end

    # `redact_with`: the field policy of every object type the value may have. Only set
    # when there is one, so the specs of schemas without redaction stay as they were.
    defp with_redactors(spec, redactors) when map_size(redactors) == 0, do: spec
    defp with_redactors(spec, redactors), do: Map.put(spec, :redactors, redactors)

    ## Redaction

    defp redactors(types) do
      for {ident, %Type.Object{} = object} <- types,
          module = meta(object, :warden_redact_with),
          module != nil,
          into: %{},
          do: {ident, module}
    end

    defp redact_errors(types, config) do
      sorted = Enum.sort_by(types, fn {ident, _type} -> ident end)

      own =
        for {ident, type} <- sorted,
            module = meta(type, :warden_redact_with),
            module != nil,
            error <- redact_type_errors(ident, type, module, config),
            do: error

      stray =
        for {_ident, %{fields: fields} = type} <- sorted,
            is_map(fields),
            {_field_ident, field} <- Enum.sort_by(fields, &elem(&1, 0)),
            meta(field, :warden_redact_with) != nil do
          "#{type.name}.#{field.name}: `redact_with` is only supported on object types"
        end

      own ++ stray
    end

    # An object type over a struct (through a `can/2` policy's `for:` or its
    # `warden_schema`) whose field policy in the authorizer's `fields:` redacts a field the
    # type exposes under the same identifier must `redact_with` that field policy: without
    # it the type serves the unredacted value. A type that exposes none of the redacted
    # fields needs nothing.
    defp missing_redaction_errors(types, config) do
      registry = Redactor.registry(config.authorizer)

      for {ident, %Type.Object{} = object} <- Enum.sort_by(types, &elem(&1, 0)),
          not introspection_type?(object),
          ident not in @root_types,
          struct_module <- linked_structs(object),
          module = Map.get(registry, struct_module),
          module != nil,
          meta(object, :warden_redact_with) != module,
          exposed = exposed_redactions(object, module),
          exposed != [] do
        fields = Enum.map_join(exposed, ", ", &inspect/1)

        """
        #{object.name} exposes #{fields} of #{inspect(struct_module)}, which \
        #{inspect(module)} redacts; add `redact_with #{inspect(module)}`\
        """
      end
    end

    defp exposed_redactions(object, module) do
      for %{field: field} <- module.__warden_fields__(:info).redactions,
          Map.has_key?(object.fields, field),
          do: field
    end

    defp redact_type_errors(ident, %Type.Object{} = object, module, config) do
      case fields_info(module) do
        {:ok, info} ->
          root_errors(ident, object) ++
            redactor_authorizer_errors(object, module, info, config) ++
            struct_errors(object, module, info) ++ nil_errors(object, module, info)

        :error ->
          error = """
          #{object.name}: `redact_with` names #{inspect(module)}, which is not a field \
          policy (use Warden.Fields)\
          """

          [error]
      end
    end

    defp redact_type_errors(_ident, type, _module, _config),
      do: ["#{type.name}: `redact_with` is only supported on object types"]

    defp fields_info(module) do
      if is_atom(module) and match?({:module, _module}, Code.ensure_compiled(module)) and
           function_exported?(module, :__warden_fields__, 1),
         do: {:ok, module.__warden_fields__(:info)},
         else: :error
    end

    defp root_errors(ident, object) when ident in @root_types,
      do: ["#{object.name}: `redact_with` is not supported on root types"]

    defp root_errors(_ident, _object), do: []

    defp redactor_authorizer_errors(object, module, info, config) do
      error = """
      #{object.name}: `redact_with` #{inspect(module)} belongs to \
      #{inspect(info.authorizer)}, not #{inspect(config.authorizer)}\
      """

      if info.authorizer == config.authorizer, do: [], else: [error]
    end

    # The structs the object type is linked to: the `for:` of every policy its own rule
    # names with `can/2,3`, and its `warden_schema`. A field policy for another struct
    # fails compilation.
    defp struct_errors(object, module, info) do
      linked = linked_structs(object)

      if linked == [] or info.for in linked do
        []
      else
        about = Enum.map_join(linked, " and ", &inspect/1)

        error = """
        #{object.name}: `redact_with` #{inspect(module)} redacts #{inspect(info.for)}, \
        but the object type is about #{about}\
        """

        [error]
      end
    end

    defp linked_structs(object) do
      from_policies =
        for {:can, policy, _action, _opts} <- rule_leaves(meta(object, :warden_rule)),
            {:ok, struct_module} <- [policy_struct(policy)],
            do: struct_module

      schema = meta(object, :warden_schema)
      from_schema = if is_atom(schema) and schema != nil, do: [schema], else: []
      Enum.uniq(from_policies ++ from_schema)
    end

    defp rule_leaves({tag, rules}) when tag in [:all, :any] and is_list(rules),
      do: Enum.flat_map(rules, &rule_leaves/1)

    defp rule_leaves(nil), do: []
    defp rule_leaves(rule), do: [rule]

    defp policy_struct(policy) do
      if is_atom(policy) and match?({:module, _module}, Code.ensure_compiled(policy)) and
           function_exported?(policy, :__warden_policy__, 1),
         do: {:ok, policy.__warden_policy__(:info).for},
         else: :error
    end

    # A redacted value of `nil` in a non-null GraphQL field (same identifier) would null
    # the whole object for every actor the rule denies.
    defp nil_errors(object, module, info) do
      for %{field: field_ident, with: nil} <- info.redactions,
          %{type: %Type.NonNull{}} = field <- [Map.get(object.fields, field_ident)] do
        """
        #{object.name}.#{field.name}: #{inspect(module)} redacts #{inspect(field_ident)} \
        with nil, but the field is non-null\
        """
      end
    end

    defp list_policy(object, field, types, config) do
      own = meta(field, :warden_list_policy)

      from_interfaces =
        for iface_ident <- List.wrap(object.interfaces),
            %{fields: ifields} <- [Map.get(types, iface_ident)],
            ifield = Map.get(ifields, field.identifier),
            ifield != nil,
            policy = meta(ifield, :warden_list_policy),
            policy != nil,
            do: policy

      own || List.first(from_interfaces) || config.list_policy
    end

    defp shape(%Type.NonNull{of_type: t}), do: {:non_null, shape(t)}
    defp shape(%Type.List{of_type: t}), do: {:list, shape(t)}
    defp shape(ident) when is_atom(ident), do: :named

    def implementors(types, interface) do
      for {ident, %Type.Object{interfaces: ifaces}} <- types,
          interface in List.wrap(ifaces),
          do: ident
    end

    ## Subscriptions

    # At subscribe time the payload is unknown, but object rules that do not depend on the
    # value (no `check`) can already be evaluated. The subscription is refused when the
    # return type's own rule denies, or when every possible concrete type has such a rule
    # and it denies: the subscriber could never see an event.
    defp subscribe_spec(pre, field, types, object_rules, config) do
      named = Type.unwrap(field.type)
      {abstract_rule, members} = return_types(named, types, object_rules)

      %{
        authorizer: config.authorizer,
        pre: pre,
        return: return_spec(named, abstract_rule, members, object_rules)
      }
    end

    # The rule of the return type itself (abstract types only) and its possible types.
    defp return_types(named, types, object_rules) do
      case Map.get(types, named) do
        %Type.Object{} -> {nil, [named]}
        %Type.Interface{} -> {Map.get(object_rules, named), implementors(types, named)}
        %Type.Union{types: members} -> {Map.get(object_rules, named), members}
        _ -> {nil, []}
      end
    end

    defp return_spec(named, abstract_rule, members, object_rules) do
      member_rules = Enum.map(Enum.sort(members), &Map.get(object_rules, &1))
      rule = if value_independent?(abstract_rule), do: abstract_rule, else: nil
      members_ok? = members != [] and Enum.all?(member_rules, &value_independent?/1)
      members = if members_ok?, do: Enum.zip(Enum.sort(members), member_rules), else: nil

      if rule == nil and members == nil,
        do: nil,
        else: %{type: named, rule: rule, members: members}
    end

    defp value_independent?(nil), do: false
    defp value_independent?(:public), do: false
    defp value_independent?(rule), do: not contains_check?(rule)

    defp contains_check?({:check, _, _}), do: true
    defp contains_check?({:can, _policy, _action, _opts}), do: true
    defp contains_check?({:tenant_role, _role, _opts}), do: true

    defp contains_check?({tag, rules}) when tag in [:all, :any],
      do: Enum.any?(rules, &contains_check?/1)

    defp contains_check?(_), do: false

    ## Validation

    defp validate_meta(types, catalog) do
      types
      |> Enum.sort_by(fn {ident, _} -> ident end)
      |> Enum.flat_map(fn {_ident, type} -> validate_type(type, types, catalog) end)
    end

    defp validate_type(%type_mod{} = type, types, catalog) do
      type_errors =
        case {type_mod, meta(type, :warden_rule)} do
          {_, nil} ->
            []

          {mod, rule} when mod in [Type.Object, Type.Interface, Type.Union] ->
            rule_errors(rule, catalog, type.name)

          {_, _} ->
            ["#{type.name}: object rules are only supported on objects, interfaces and unions"]
        end

      stray =
        for key <- [:warden_args, :warden_list_policy, :warden_on_deny], meta(type, key) != nil do
          "#{type.name}: #{inspect(key)} is only supported on object fields"
        end

      field_errors =
        case type do
          %{fields: fields} when is_map(fields) ->
            fields
            |> Enum.sort_by(fn {ident, _} -> ident end)
            |> Enum.flat_map(fn {_, field} -> validate_field(type, field, types, catalog) end)

          _ ->
            []
        end

      type_errors ++ stray ++ field_errors
    end

    defp validate_field(%type_mod{} = type, field, _types, catalog) do
      where = "#{type.name}.#{field.name}"

      optional_rule_errors(meta(field, :warden_rule), catalog, where) ++
        field_args_errors(type_mod, meta(field, :warden_args), field, where, catalog) ++
        list_policy_errors(type_mod, meta(field, :warden_list_policy), where) ++
        on_deny_errors(type_mod, meta(field, :warden_on_deny), field, where) ++
        arg_rule_errors(field, where, catalog)
    end

    defp optional_rule_errors(nil, _catalog, _where), do: []
    defp optional_rule_errors(rule, catalog, where), do: rule_errors(rule, catalog, where)

    defp field_args_errors(_type_mod, nil, _field, _where, _catalog), do: []

    defp field_args_errors(Type.InputObject, _rules, _field, where, _catalog),
      do: ["#{where}: `authorize_args` is not supported on input object fields"]

    defp field_args_errors(_type_mod, rules, field, where, catalog) when is_map(rules) do
      Enum.flat_map(rules, fn {arg, rule} ->
        if Map.has_key?(field.args, arg),
          do: rule_errors(rule, catalog, "#{where}(#{arg})"),
          else: ["#{where}: `authorize_args` names #{inspect(arg)}, which is not an argument"]
      end)
    end

    defp field_args_errors(_type_mod, other, _field, where, _catalog),
      do: ["#{where}: invalid :warden_args meta #{inspect(other)}"]

    defp list_policy_errors(_type_mod, nil, _where), do: []

    defp list_policy_errors(Type.InputObject, _policy, where),
      do: ["#{where}: `list_policy` is not supported on input object fields"]

    defp list_policy_errors(_type_mod, policy, where) do
      if policy in Rules.list_policies(),
        do: [],
        else: ["#{where}: invalid list policy #{inspect(policy)}"]
    end

    defp on_deny_errors(_type_mod, nil, _field, _where), do: []

    defp on_deny_errors(Type.InputObject, _on_deny, _field, where),
      do: ["#{where}: `on_deny:` is not supported on input object fields"]

    defp on_deny_errors(_type_mod, on_deny, field, where) do
      cond do
        not Rules.valid_on_deny?(on_deny) ->
          ["#{where}: invalid `on_deny:` #{inspect(on_deny)}"]

        meta(field, :warden_rule) == nil ->
          ["#{where}: `on_deny:` needs a field rule"]

        on_deny == :null and match?(%Type.NonNull{}, field.type) ->
          ["#{where}: `on_deny: :null` on a non-null field; the field cannot be null"]

        true ->
          []
      end
    end

    # An object rule decides a value, wherever it is returned; the arguments of the field
    # that returned it are the client's choice and say nothing about the value. So the
    # leaves that read field arguments (`tenant_role(r, tenant: {:arg, path})` and
    # `can(policy, action, arg: path)`) are only allowed in field and argument rules.
    defp argument_leaf_errors(types) do
      for {_ident, %type_mod{} = type} <- Enum.sort_by(types, &elem(&1, 0)),
          type_mod in [Type.Object, Type.Interface, Type.Union],
          Warden.Rule.reads_arguments?(meta(type, :warden_rule)) do
        """
        #{type.name}: an object rule cannot read field arguments \
        (tenant_role(_, tenant: {:arg, _}) or can(_, _, arg: _)); use them in a field or \
        argument rule\
        """
      end
    end

    # `covered()` says "the object rule guards this field", so it stands alone as a field
    # rule, on a field of an object type or interface that has an object rule. Anywhere
    # else it would be a `public()` in disguise.
    defp covered_errors(types, object_rules) do
      types
      |> Enum.sort_by(fn {ident, _type} -> ident end)
      |> Enum.flat_map(fn {ident, type} -> type_covered_errors(ident, type, object_rules) end)
    end

    defp type_covered_errors(_ident, %{name: "__" <> _introspection}, _object_rules), do: []

    defp type_covered_errors(ident, %type_mod{} = type, object_rules) do
      own =
        if contains_covered?(meta(type, :warden_rule)),
          do: ["#{type.name}: covered() is only for fields, not object rules"],
          else: []

      fields =
        case type do
          %{fields: fields} when is_map(fields) ->
            guarded? =
              type_mod in [Type.Object, Type.Interface] and Map.has_key?(object_rules, ident)

            fields
            |> Enum.sort_by(fn {field_ident, _field} -> field_ident end)
            |> Enum.flat_map(fn {_field_ident, field} ->
              field_covered_errors(type, field, guarded?)
            end)

          _ ->
            []
        end

      own ++ fields
    end

    defp field_covered_errors(type, field, guarded?) do
      where = "#{type.name}.#{field.name}"
      arg_rules = Map.values(meta(field, :warden_args) || %{})
      on_args = for {_ident, arg} <- Map.get(field, :args) || %{}, do: meta(arg, :warden_rule)

      arg_errors =
        if Enum.any?(arg_rules ++ on_args, &contains_covered?/1),
          do: ["#{where}: covered() is not an argument rule"],
          else: []

      field_rule_covered_errors(meta(field, :warden_rule), type, where, guarded?) ++ arg_errors
    end

    defp field_rule_covered_errors(:covered, _type, _where, true), do: []

    defp field_rule_covered_errors(:covered, type, where, false),
      do: ["#{where}: covered() needs an object rule on #{type.name}; use public() or a rule"]

    defp field_rule_covered_errors(rule, _type, where, _guarded?) do
      if contains_covered?(rule),
        do: ["#{where}: covered() must be the whole field rule, not part of all_of/any_of"],
        else: []
    end

    defp contains_covered?(:covered), do: true

    defp contains_covered?({tag, rules}) when tag in [:all, :any] and is_list(rules),
      do: Enum.any?(rules, &contains_covered?/1)

    defp contains_covered?(_rule), do: false

    defp arg_rule_errors(field, where, catalog) do
      for {ident, arg} <- Enum.sort_by(Map.get(field, :args) || %{}, &elem(&1, 0)),
          error <- validate_arg(arg, "#{where}(#{ident})", catalog),
          do: error
    end

    defp validate_arg(arg, where, catalog) do
      rule =
        case meta(arg, :warden_rule) do
          nil -> []
          rule -> rule_errors(rule, catalog, where)
        end

      stray =
        for key <- [:warden_args, :warden_list_policy, :warden_on_deny, :warden_redact_with],
            meta(arg, key) != nil do
          "#{where}: #{inspect(key)} is not supported on an argument"
        end

      rule ++ stray
    end

    defp rule_errors(rule, catalog, where) do
      case Rule.validate(rule, catalog) do
        :ok -> []
        {:error, errors} -> Enum.map(errors, &"#{where}: #{&1}")
      end
    end

    ## Strict mode

    defp strict_errors(_types, %{strict_mode: false}), do: []

    defp strict_errors(types, %{strict_mode: mode}) do
      for {ident, %Type.Object{} = object} <- Enum.sort_by(types, &elem(&1, 0)),
          not introspection_type?(object),
          mode == :all or ident in @root_types,
          {_, field} <- Enum.sort_by(object.fields, &elem(&1, 0)),
          not introspection_field?(field),
          effective_field_rule_declared?(object, field, types) == false do
        "#{object.name}.#{field.name}: no rule declared (strict_mode: #{inspect(mode)})"
      end
    end

    defp effective_field_rule_declared?(object, field, types) do
      meta(field, :warden_rule) != nil or
        Enum.any?(interface_fields(object, field, types), &(meta(&1, :warden_rule) != nil))
    end
  end
end
