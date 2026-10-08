defmodule Warden.Plan do
  @moduledoc false
  # Computes, from the schema's types and the Warden configuration, which Warden
  # middleware every field needs. The same function runs in the schema pipeline (to
  # attach the middleware) and after compilation (to verify the compiled schema), so the
  # two can be compared exactly.

  alias Absinthe.Type
  alias Warden.Rule

  @root_types [:query, :mutation, :subscription]
  # GraphQL names of the fields Absinthe's introspection adds. Matched by name, never by
  # identifier prefix: a user field `:__internal` named "internal" is an ordinary field.
  @introspection_fields ["__typename", "__schema", "__type"]
  @introspection_schema_fields ["__schema", "__type"]

  defstruct fields: %{}, subscriptions: %{}, object_rules: %{}, errors: []

  @type t :: %__MODULE__{}

  @doc false
  def root_types, do: @root_types

  @doc """
  Builds the plan. `types` maps identifiers to `Absinthe.Type` structs. Returns the plan;
  `plan.errors` lists every problem found (catalog, placement, strict mode).
  """
  def build(types, config) do
    catalog = config.catalog
    errors = validate_meta(types, catalog)

    object_rules = object_rules(types, config)
    inputs = input_plans(types)

    {fields, subs} =
      for {_, %Type.Object{} = object} <- types,
          not introspection_type?(object),
          {_, field} <- object.fields,
          reduce: {%{}, %{}} do
        {fields, subs} ->
          pre = pre_spec(object, field, types, object_rules, inputs, config)
          post = post_spec(object, field, types, object_rules, config)

          fields =
            if pre || post,
              do: Map.put(fields, {object.identifier, field.identifier}, {pre, post}),
              else: fields

          subs =
            if object.identifier == :subscription and not introspection_field?(field),
              do: Map.put(subs, field.identifier, subscribe_spec(pre, config)),
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
    for {ident, type} <- types, reduce: %{} do
      acc ->
        rule =
          case type do
            %Type.Object{} = object ->
              own = meta(object, :warden_rule)

              own =
                if own == nil and not introspection_type?(object) and
                     ident not in @root_types,
                   do: config.default_object_rule,
                   else: own

              interface_rules =
                object.interfaces
                |> List.wrap()
                |> Enum.map(
                  &(types
                    |> Map.get(&1)
                    |> then(fn i -> i && meta(i, :warden_rule) end))
                )

              Rule.conjoin([own | interface_rules])

            %Type.Interface{} = interface ->
              Rule.conjoin([meta(interface, :warden_rule)])

            %Type.Union{} = union ->
              Rule.conjoin([meta(union, :warden_rule)])

            _ ->
              nil
          end

        if rule, do: Map.put(acc, ident, rule), else: acc
    end
  end

  ## Pre

  defp pre_spec(object, field, types, object_rules, inputs, config) do
    root? = object.identifier in @root_types

    root_rule =
      case root? && Map.get(object_rules, object.identifier) do
        rule when rule not in [nil, false] -> [{:object, object.identifier, rule}]
        _ -> []
      end

    checks =
      cond do
        # Absinthe adds `__schema` and `__type` to every object named like a query root,
        # so the introspection rule guards them wherever they appear. A root object rule
        # applies too.
        field.name in @introspection_schema_fields ->
          parent =
            case Map.get(object_rules, object.identifier) do
              nil -> []
              rule -> [{:object, object.identifier, rule}]
            end

          introspection =
            case config.introspection do
              :public -> []
              rule -> [{:introspection, rule}]
            end

          parent ++ introspection

        # `__typename` of a root type is guarded by the root's object rule.
        introspection_field?(field) ->
          root_rule

        true ->
          parent =
            case Map.get(object_rules, object.identifier) do
              nil -> []
              rule -> [{:object, object.identifier, rule}]
            end

          field_rule =
            case effective_field_rule(object, field, types) do
              nil -> []
              rule -> [{:field, rule}]
            end

          args =
            case arg_plan(object, field, types, inputs) do
              nil -> []
              plan -> [{:args, plan}]
            end

          parent ++ field_rule ++ args
      end

    case checks do
      [] ->
        nil

      checks ->
        %{
          authorizer: config.authorizer,
          root: root?,
          checks: checks
        }
    end
  end

  @doc false
  def effective_field_rule(object, field, types) do
    interface_rules =
      for iface_ident <- List.wrap(object.interfaces),
          %{fields: ifields} <- [Map.get(types, iface_ident)],
          ifield = Map.get(ifields, field.identifier),
          ifield != nil do
        meta(ifield, :warden_rule)
      end

    Rule.conjoin([meta(field, :warden_rule) | interface_rules])
  end

  defp effective_arg_rules(object, field, types) do
    interface_args =
      for iface_ident <- List.wrap(object.interfaces),
          %{fields: ifields} <- [Map.get(types, iface_ident)],
          ifield = Map.get(ifields, field.identifier),
          ifield != nil do
        meta(ifield, :warden_args) || %{}
      end

    Enum.reduce(interface_args, meta(field, :warden_args) || %{}, fn rules, acc ->
      Map.merge(acc, rules, fn _k, a, b -> Rule.conjoin([a, b]) end)
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
  # concrete field then runs with them. `defaults` holds every declared non-nil default
  # (a value is restricted if it differs from any of them); `input_specs` holds the input
  # type walk of every declaration.
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

        defaults =
          decls
          |> Enum.map(& &1.default_value)
          |> Enum.reject(&is_nil/1)
          |> Enum.uniq()

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
    |> close_over(inputs, MapSet.new())
    |> Enum.sort()
  end

  defp close_over([], _inputs, seen), do: seen

  defp close_over([ident | rest], inputs, seen) do
    if MapSet.member?(seen, ident) do
      close_over(rest, inputs, seen)
    else
      nested =
        inputs
        |> Map.fetch!(ident)
        |> Enum.flat_map(fn {_, _, _, specs} -> Enum.flat_map(specs, &spec_inputs/1) end)

      close_over(nested ++ rest, inputs, MapSet.put(seen, ident))
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
        |> Enum.flat_map(fn {fident, f} ->
          rule =
            case meta(f, :warden_rule) do
              :public -> nil
              r -> r
            end

          specs = List.wrap(input_ref_spec(f.type, with_rules))
          defaults = if f.default_value == nil, do: [], else: [f.default_value]

          if rule == nil and specs == [],
            do: [],
            else: [{fident, rule, defaults, specs}]
        end)

      {ident, fields}
    end)
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

  defp post_spec(object, field, types, object_rules, config) do
    if introspection_field?(field) do
      nil
    else
      named = Type.unwrap(field.type)
      shape = shape(field.type)

      # For abstract types the concrete type comes from user code (`resolve_type`), which
      # may return a type outside the declared members. Every object rule is therefore
      # in reach of an abstract field.
      object_type_rules =
        for {ident, rule} <- object_rules,
            match?(%Type.Object{}, Map.get(types, ident)),
            into: %{},
            do: {ident, rule}

      {abstract_rule, concrete_rules, abstract_kind} =
        case Map.get(types, named) do
          %Type.Object{} ->
            {nil, Map.take(object_rules, [named]), nil}

          %Type.Interface{} ->
            {Map.get(object_rules, named), object_type_rules, :interface}

          %Type.Union{} ->
            {Map.get(object_rules, named), object_type_rules, :union}

          _ ->
            {nil, %{}, nil}
        end

      if abstract_rule == nil and map_size(concrete_rules) == 0 do
        nil
      else
        %{
          authorizer: config.authorizer,
          shape: shape,
          named: named,
          abstract: abstract_kind,
          abstract_rule: abstract_rule,
          rules: concrete_rules,
          list_policy: list_policy(object, field, types, config)
        }
      end
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

  @doc false
  def implementors(types, interface) do
    for {ident, %Type.Object{interfaces: ifaces}} <- types,
        interface in List.wrap(ifaces),
        do: ident
  end

  ## Subscriptions

  defp subscribe_spec(pre, config) do
    %{authorizer: config.authorizer, pre: pre}
  end

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
      for key <- [:warden_args, :warden_list_policy], meta(type, key) != nil do
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

    rule_errors =
      case meta(field, :warden_rule) do
        nil -> []
        rule -> rule_errors(rule, catalog, where)
      end

    args_errors =
      case meta(field, :warden_args) do
        nil ->
          []

        rules when type_mod == Type.InputObject ->
          _ = rules
          ["#{where}: `authorize_args` is not supported on input object fields"]

        rules when is_map(rules) ->
          Enum.flat_map(rules, fn {arg, rule} ->
            if Map.has_key?(field.args, arg) do
              rule_errors(rule, catalog, "#{where}(#{arg})")
            else
              ["#{where}: `authorize_args` names #{inspect(arg)}, which is not an argument"]
            end
          end)

        other ->
          ["#{where}: invalid :warden_args meta #{inspect(other)}"]
      end

    policy_errors =
      case meta(field, :warden_list_policy) do
        nil ->
          []

        _ when type_mod == Type.InputObject ->
          ["#{where}: `list_policy` is not supported on input object fields"]

        policy ->
          if policy in Rule.list_policies(),
            do: [],
            else: ["#{where}: invalid list policy #{inspect(policy)}"]
      end

    rule_errors ++ args_errors ++ policy_errors
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
      Enum.any?(List.wrap(object.interfaces), fn iface ->
        case Map.get(types, iface) do
          %{fields: %{} = ifields} ->
            case Map.get(ifields, field.identifier) do
              nil -> false
              ifield -> meta(ifield, :warden_rule) != nil
            end

          _ ->
            false
        end
      end)
  end
end
