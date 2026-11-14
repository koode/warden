defmodule Warden.Authorizer.Catalog do
  @moduledoc false
  # Validates the options of `use Warden.Authorizer` and builds the catalog. Every check
  # returns a list of error messages, so all problems are reported at once.

  @option_keys [
    :roles,
    :permissions,
    :role_hierarchy,
    :role_permissions,
    :checks,
    :kinds,
    :tenant_roles,
    :tenant_role_hierarchy,
    :credential_scopes,
    :policies,
    :expose_denial_reasons,
    :spec_compliant_errors
  ]

  @check_spec_keys [:batch, :timeout, :opts, :required, :system_kinds]
  @default_check_spec %{batch: false, timeout: nil, opts: nil, required: [], system_kinds: []}
  @scalar_opt_types [:atom, :string, :integer, :boolean, :any]

  # `:user` is always declared; `:anonymous` is the kind of an actor without a subject and
  # cannot be declared.
  @always_declared_kind :user
  @reserved_kind :anonymous

  @spec default_check_spec() :: map
  def default_check_spec, do: @default_check_spec

  @spec build(term) :: {:ok, map} | {:error, [String.t()]}
  def build(opts) when is_list(opts) do
    roles = Keyword.get(opts, :roles)
    perms = Keyword.get(opts, :permissions)
    hierarchy = Keyword.get(opts, :role_hierarchy, %{})
    role_perms = Keyword.get(opts, :role_permissions, %{})
    checks = Keyword.get(opts, :checks, [])
    kinds = Keyword.get(opts, :kinds, [@always_declared_kind])
    tenant_roles = Keyword.get(opts, :tenant_roles)
    tenant_hierarchy = Keyword.get(opts, :tenant_role_hierarchy, %{})
    scopes = Keyword.get(opts, :credential_scopes)
    policies = Keyword.get(opts, :policies, [])

    role_set = if is_list(roles), do: MapSet.new(roles), else: MapSet.new()
    perm_set = if is_list(perms), do: MapSet.new(perms), else: nil
    kind_list = kind_list(kinds)
    tenant_role_set = if is_list(tenant_roles), do: MapSet.new(tenant_roles), else: MapSet.new()

    errors =
      unknown_option_errors(opts) ++
        roles_errors(roles) ++
        permissions_errors(perms)

    errors = errors ++ hierarchy_errors(hierarchy, role_set)
    # A cycle is only looked for in an otherwise valid hierarchy.
    errors = if errors == [], do: cycle_errors(hierarchy), else: errors

    errors =
      errors ++
        role_permissions_errors(role_perms, role_set, perm_set) ++
        kinds_errors(kinds) ++
        checks_errors(checks, kind_list) ++
        tenant_roles_errors(tenant_roles, tenant_hierarchy, tenant_role_set) ++
        credential_scopes_errors(scopes) ++
        policies_errors(policies) ++
        boolean_errors(opts)

    case errors do
      [] ->
        tenant_roles_declared = if is_list(tenant_roles), do: tenant_role_set, else: nil

        catalog = %{
          roles: role_set,
          permissions: perm_set,
          role_hierarchy: hierarchy,
          implied_roles: Map.new(roles, &{&1, reachable(&1, hierarchy)}),
          role_permissions: role_perms,
          checks: check_names(checks),
          check_specs: check_specs(checks),
          kinds: MapSet.new(kind_list),
          tenant_roles: tenant_roles_declared,
          tenant_role_hierarchy: tenant_hierarchy,
          implied_tenant_roles:
            Map.new(List.wrap(tenant_roles), &{&1, reachable(&1, tenant_hierarchy)}),
          credential_scopes: if(is_list(scopes), do: MapSet.new(scopes), else: nil),
          policies: policies,
          expose_denial_reasons: Keyword.get(opts, :expose_denial_reasons, false),
          spec_compliant_errors: Keyword.get(opts, :spec_compliant_errors, false)
        }

        {:ok, catalog}

      errors ->
        {:error, errors}
    end
  end

  def build(_), do: {:error, ["options must be a keyword list"]}

  defp unknown_option_errors(opts) do
    case Keyword.keys(opts) -- @option_keys do
      [] -> []
      unknown -> ["unknown options: #{inspect(unknown)}"]
    end
  end

  defp roles_errors(nil), do: ["`:roles` is required"]

  defp roles_errors(roles) when not is_list(roles) or roles == [],
    do: ["`:roles` must be a non-empty list of atoms"]

  defp roles_errors(roles) do
    cond do
      Enum.any?(roles, &(not is_atom(&1) or is_nil(&1) or is_boolean(&1))) ->
        ["`:roles` must be a non-empty list of atoms, got: #{inspect(roles)}"]

      length(Enum.uniq(roles)) != length(roles) ->
        ["`:roles` contains duplicates: #{inspect(roles -- Enum.uniq(roles))}"]

      true ->
        []
    end
  end

  defp permissions_errors(nil), do: []

  defp permissions_errors(perms) when not is_list(perms),
    do: ["`:permissions` must be a list or nil"]

  defp permissions_errors(perms) do
    if Enum.any?(perms, &(&1 in [nil, :all])),
      do: ["`:permissions` must not contain nil or :all"],
      else: []
  end

  defp boolean_errors(opts) do
    for key <- [:expose_denial_reasons, :spec_compliant_errors],
        not is_boolean(Keyword.get(opts, key, false)),
        do: "`#{inspect(key)}` must be a boolean"
  end

  defp plain_atom?(term), do: is_atom(term) and not is_nil(term) and not is_boolean(term)

  defp duplicates(list), do: list -- Enum.uniq(list)

  # The declared kinds: `:user` always, `:anonymous` never.
  defp kind_list(kinds) when is_list(kinds) do
    declared = for kind <- kinds, plain_atom?(kind), kind != @reserved_kind, do: kind
    Enum.uniq([@always_declared_kind | declared])
  end

  defp kind_list(_kinds), do: [@always_declared_kind]

  defp kinds_errors(kinds) when is_list(kinds) do
    cond do
      not Enum.all?(kinds, &plain_atom?/1) ->
        ["`:kinds` must be a list of atoms, got: #{inspect(kinds)}"]

      @reserved_kind in kinds ->
        ["`:kinds` must not contain :anonymous (the kind of an actor without a subject)"]

      duplicates(kinds) != [] ->
        ["`:kinds` contains duplicates: #{inspect(duplicates(kinds))}"]

      true ->
        []
    end
  end

  defp kinds_errors(_kinds), do: ["`:kinds` must be a list of atoms"]

  # A check entry is a name (an atom) or `name: options`. Duplicate names are accepted only
  # when every entry for the name is the same.
  defp checks_errors(checks, kinds) when is_list(checks) do
    entry_errors = Enum.flat_map(checks, &check_entry_errors(&1, kinds))

    conflicting =
      checks
      |> Enum.filter(&valid_check_entry?/1)
      |> Enum.map(&normalize_check_entry/1)
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Enum.filter(fn {_name, specs} -> match?([_, _ | _], Enum.uniq(specs)) end)
      |> Enum.map(fn {name, _specs} -> "`:checks` declares #{inspect(name)} twice" end)

    entry_errors ++ conflicting
  end

  defp checks_errors(_checks, _kinds),
    do: ["`:checks` must be a list of atoms and `name: options` entries"]

  defp valid_check_entry?(name) when is_atom(name), do: plain_atom?(name)
  defp valid_check_entry?({name, spec}), do: plain_atom?(name) and Keyword.keyword?(spec)
  defp valid_check_entry?(_entry), do: false

  defp check_entry_errors(name, _kinds) when is_atom(name) do
    if plain_atom?(name),
      do: [],
      else: ["`:checks` must be a list of atoms and `name: options` entries"]
  end

  defp check_entry_errors({name, spec}, kinds) when is_atom(name) and is_list(spec) do
    if plain_atom?(name) and Keyword.keyword?(spec),
      do: check_spec_errors(name, spec, kinds),
      else: ["`:checks` entry #{inspect(name)} must be `name: [options]`"]
  end

  defp check_entry_errors(entry, _kinds),
    do: ["`:checks` entry #{inspect(entry)} must be an atom or `name: [options]`"]

  defp check_spec_errors(name, spec, kinds) do
    unknown =
      case Keyword.keys(spec) -- @check_spec_keys do
        [] -> []
        keys -> ["check #{inspect(name)}: unknown options #{inspect(keys)}"]
      end

    unknown ++
      batch_errors(name, Keyword.get(spec, :batch, false)) ++
      timeout_errors(name, Keyword.get(spec, :timeout)) ++
      opts_schema_errors(name, Keyword.get(spec, :opts)) ++
      required_errors(name, Keyword.get(spec, :required, []), Keyword.get(spec, :opts)) ++
      system_kinds_errors(name, Keyword.get(spec, :system_kinds, []), kinds)
  end

  defp batch_errors(_name, batch) when is_boolean(batch), do: []
  defp batch_errors(name, _batch), do: ["check #{inspect(name)}: `batch:` must be a boolean"]

  defp timeout_errors(_name, nil), do: []
  defp timeout_errors(_name, timeout) when is_integer(timeout) and timeout > 0, do: []

  defp timeout_errors(name, _timeout),
    do: ["check #{inspect(name)}: `timeout:` must be a positive integer (milliseconds)"]

  defp opts_schema_errors(_name, nil), do: []

  defp opts_schema_errors(name, schema) do
    if Keyword.keyword?(schema) do
      for {key, type} <- schema, not valid_opt_type?(type) do
        "check #{inspect(name)}: option #{inspect(key)} has an unknown type #{inspect(type)}"
      end ++ duplicate_key_errors(name, Keyword.keys(schema))
    else
      ["check #{inspect(name)}: `opts:` must be a keyword list of option: type"]
    end
  end

  defp duplicate_key_errors(name, keys) do
    case duplicates(keys) do
      [] -> []
      dupes -> ["check #{inspect(name)}: `opts:` names #{inspect(dupes)} twice"]
    end
  end

  defp valid_opt_type?(type) when type in @scalar_opt_types, do: true
  defp valid_opt_type?({:in, [_ | _] = allowed}) when is_list(allowed), do: true
  defp valid_opt_type?({:list, type}), do: valid_opt_type?(type)
  defp valid_opt_type?(_type), do: false

  # The errors of the options a rule gives to check `name`, against the check's `opts:`
  # schema. A check without a schema accepts any options.
  @spec check_options_errors(atom, keyword, map) :: [String.t()]
  def check_options_errors(_name, _options, %{opts: nil}), do: []

  def check_options_errors(name, options, %{opts: schema, required: required}) do
    unknown =
      for {key, _value} <- options, not Keyword.has_key?(schema, key) do
        "check(#{inspect(name)}) has an unknown option #{inspect(key)}"
      end

    missing =
      for key <- required, not Keyword.has_key?(options, key) do
        "check(#{inspect(name)}) needs the option #{inspect(key)}"
      end

    mistyped =
      for {key, value} <- options,
          type = Keyword.get(schema, key),
          type != nil,
          not opt_type_matches?(type, value) do
        """
        check(#{inspect(name)}) option #{inspect(key)} must be #{inspect(type)}, \
        got: #{inspect(value)}\
        """
      end

    unknown ++ missing ++ mistyped
  end

  defp opt_type_matches?(:any, _value), do: true
  defp opt_type_matches?(:atom, value), do: is_atom(value)
  defp opt_type_matches?(:string, value), do: is_binary(value)
  defp opt_type_matches?(:integer, value), do: is_integer(value)
  defp opt_type_matches?(:boolean, value), do: is_boolean(value)
  defp opt_type_matches?({:in, allowed}, value), do: value in allowed

  defp opt_type_matches?({:list, type}, values) when is_list(values),
    do: Enum.all?(values, &opt_type_matches?(type, &1))

  defp opt_type_matches?({:list, _type}, _value), do: false

  defp required_errors(_name, [], _schema), do: []

  defp required_errors(name, required, schema) when is_list(required) do
    declared = if Keyword.keyword?(schema || []), do: Keyword.keys(schema || []), else: []

    cond do
      not Enum.all?(required, &plain_atom?/1) ->
        ["check #{inspect(name)}: `required:` must be a list of option names"]

      schema == nil ->
        ["check #{inspect(name)}: `required:` needs an `opts:` schema"]

      true ->
        for key <- required, key not in declared do
          "check #{inspect(name)}: required option #{inspect(key)} is not in `opts:`"
        end
    end
  end

  defp required_errors(name, _required, _schema),
    do: ["check #{inspect(name)}: `required:` must be a list of option names"]

  defp system_kinds_errors(name, system_kinds, kinds) when is_list(system_kinds) do
    for kind <- system_kinds, not system_kind?(kind, kinds) do
      """
      check #{inspect(name)}: `system_kinds:` names #{inspect(kind)}, which is not a \
      declared kind other than :user\
      """
    end
  end

  defp system_kinds_errors(name, _system_kinds, _kinds),
    do: ["check #{inspect(name)}: `system_kinds:` must be a list of kinds"]

  # `kinds` is a plain list: Dialyzer on OTP 29 rejects a MapSet passed through closures
  # as an opaque-type mismatch.
  defp system_kind?(kind, kinds), do: kind != @always_declared_kind and kind in kinds

  defp normalize_check_entry(name) when is_atom(name), do: {name, []}
  defp normalize_check_entry({name, spec}), do: {name, Enum.sort(spec)}

  defp check_names(checks) do
    checks
    |> Enum.map(fn entry -> entry |> normalize_check_entry() |> elem(0) end)
    |> Enum.uniq()
  end

  defp check_specs(checks) do
    Map.new(checks, fn entry ->
      {name, spec} = normalize_check_entry(entry)

      check_spec = %{
        batch: Keyword.get(spec, :batch, false),
        timeout: Keyword.get(spec, :timeout),
        opts: Keyword.get(spec, :opts),
        required: Keyword.get(spec, :required, []),
        system_kinds: Keyword.get(spec, :system_kinds, [])
      }

      {name, check_spec}
    end)
  end

  defp tenant_roles_errors(nil, hierarchy, _tenant_role_set) when hierarchy == %{}, do: []

  defp tenant_roles_errors(nil, _hierarchy, _tenant_role_set),
    do: ["`:tenant_role_hierarchy` needs `:tenant_roles`"]

  defp tenant_roles_errors(tenant_roles, hierarchy, tenant_role_set) do
    list_errors =
      cond do
        not is_list(tenant_roles) or tenant_roles == [] or
            not Enum.all?(tenant_roles, &plain_atom?/1) ->
          ["`:tenant_roles` must be a non-empty list of atoms, got: #{inspect(tenant_roles)}"]

        duplicates(tenant_roles) != [] ->
          ["`:tenant_roles` contains duplicates: #{inspect(duplicates(tenant_roles))}"]

        true ->
          []
      end

    errors =
      list_errors ++
        hierarchy_errors(hierarchy, tenant_role_set, ":tenant_role_hierarchy", "tenant role")

    if errors == [],
      do: cycle_errors(hierarchy, ":tenant_role_hierarchy"),
      else: errors
  end

  defp credential_scopes_errors(nil), do: []

  defp credential_scopes_errors(scopes) when is_list(scopes) do
    cond do
      not Enum.all?(scopes, &is_binary/1) ->
        ["`:credential_scopes` must be a list of strings, got: #{inspect(scopes)}"]

      duplicates(scopes) != [] ->
        ["`:credential_scopes` contains duplicates: #{inspect(duplicates(scopes))}"]

      true ->
        []
    end
  end

  defp credential_scopes_errors(_scopes),
    do: ["`:credential_scopes` must be a list of strings or nil"]

  # Policies are only named here: the authorizer must not depend on its policy modules at
  # compile time (each policy names its authorizer, so that would be a cycle). They are
  # checked when a rule or a lookup uses them.
  defp policies_errors(policies) when is_list(policies) do
    cond do
      not Enum.all?(policies, &plain_atom?/1) ->
        ["`:policies` must be a list of modules, got: #{inspect(policies)}"]

      duplicates(policies) != [] ->
        ["`:policies` contains duplicates: #{inspect(duplicates(policies))}"]

      true ->
        []
    end
  end

  defp policies_errors(_policies), do: ["`:policies` must be a list of modules"]

  defp hierarchy_errors(hierarchy, role_set),
    do: hierarchy_errors(hierarchy, role_set, ":role_hierarchy", "catalog role")

  defp hierarchy_errors(hierarchy, role_set, option, noun) when is_map(hierarchy) do
    Enum.flat_map(hierarchy, fn {role, implied} ->
      hierarchy_key_errors(role, role_set, option, noun) ++
        hierarchy_value_errors(role, implied, role_set, option, noun)
    end)
  end

  defp hierarchy_errors(_hierarchy, _role_set, option, _noun),
    do: ["`#{option}` must be a map"]

  defp hierarchy_key_errors(role, role_set, option, noun) do
    if MapSet.member?(role_set, role),
      do: [],
      else: ["`#{option}` key #{inspect(role)} is not a #{noun}"]
  end

  defp hierarchy_value_errors(role, implied, _role_set, option, noun) when not is_list(implied),
    do: ["`#{option}` value for #{inspect(role)} must be a list of #{noun}s"]

  defp hierarchy_value_errors(role, implied, role_set, option, noun) do
    for implied_role <- implied, not MapSet.member?(role_set, implied_role) do
      "`#{option}` #{inspect(role)} implies #{inspect(implied_role)}, which is not a #{noun}"
    end
  end

  defp cycle_errors(hierarchy), do: cycle_errors(hierarchy, ":role_hierarchy")

  defp cycle_errors(hierarchy, option) when is_map(hierarchy) do
    case find_cycle(hierarchy) do
      nil -> []
      cycle -> ["`#{option}` has a cycle: #{Enum.map_join(cycle, " -> ", &inspect/1)}"]
    end
  end

  defp cycle_errors(_hierarchy, _option), do: []

  # Depth-first search for a cycle. Returns the cycle as a list of roles, or nil.
  defp find_cycle(hierarchy) do
    hierarchy
    |> Map.keys()
    |> Enum.sort()
    |> Enum.find_value(fn role -> dfs(role, hierarchy, [role]) end)
  end

  defp dfs(role, hierarchy, stack) do
    hierarchy
    |> Map.get(role, [])
    |> Enum.find_value(&dfs_step(&1, hierarchy, stack))
  end

  defp dfs_step(next, hierarchy, stack) do
    if next in stack,
      do: Enum.reverse([next | stack]),
      else: dfs(next, hierarchy, [next | stack])
  end

  # The visited set is a plain map: Dialyzer on OTP 29 rejects a MapSet threaded through
  # a recursive call as an opaque-type mismatch.
  defp reachable(role, hierarchy) do
    [role] |> reachable(hierarchy, %{}) |> Map.keys() |> MapSet.new()
  end

  defp reachable([], _hierarchy, seen), do: seen

  defp reachable([role | rest], hierarchy, seen) do
    if Map.has_key?(seen, role) do
      reachable(rest, hierarchy, seen)
    else
      reachable(Map.get(hierarchy, role, []) ++ rest, hierarchy, Map.put(seen, role, true))
    end
  end

  defp role_permissions_errors(role_perms, role_set, perm_set) when is_map(role_perms) do
    Enum.flat_map(role_perms, fn {role, perms} ->
      role_permissions_key_errors(role, role_set) ++
        role_permissions_value_errors(role, perms, perm_set)
    end)
  end

  defp role_permissions_errors(_, _, _), do: ["`:role_permissions` must be a map"]

  defp role_permissions_key_errors(role, role_set) do
    if MapSet.member?(role_set, role),
      do: [],
      else: ["`:role_permissions` key #{inspect(role)} is not a catalog role"]
  end

  defp role_permissions_value_errors(_role, :all, _perm_set), do: []

  defp role_permissions_value_errors(role, perms, _perm_set) when not is_list(perms),
    do: ["`:role_permissions` value for #{inspect(role)} must be a list or :all"]

  defp role_permissions_value_errors(role, perms, perm_set) do
    cond do
      Enum.any?(perms, &(&1 in [nil, :all])) ->
        ["`:role_permissions` for #{inspect(role)} must not contain nil or :all"]

      perm_set == nil ->
        []

      true ->
        for p <- perms, not MapSet.member?(perm_set, p) do
          "`:role_permissions` for #{inspect(role)} names #{inspect(p)}, " <>
            "which is not in the permission catalog"
        end
    end
  end
end
