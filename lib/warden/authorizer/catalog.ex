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
    :expose_denial_reasons,
    :spec_compliant_errors
  ]

  @spec build(term) :: {:ok, map} | {:error, [String.t()]}
  def build(opts) when is_list(opts) do
    roles = Keyword.get(opts, :roles)
    perms = Keyword.get(opts, :permissions)
    hierarchy = Keyword.get(opts, :role_hierarchy, %{})
    role_perms = Keyword.get(opts, :role_permissions, %{})
    checks = Keyword.get(opts, :checks, [])

    role_set = if is_list(roles), do: MapSet.new(roles), else: MapSet.new()
    perm_set = if is_list(perms), do: MapSet.new(perms), else: nil

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
        checks_errors(checks) ++
        boolean_errors(opts)

    case errors do
      [] ->
        {:ok,
         %{
           roles: role_set,
           permissions: perm_set,
           role_hierarchy: hierarchy,
           implied_roles: Map.new(roles, &{&1, reachable(&1, hierarchy)}),
           role_permissions: role_perms,
           checks: checks,
           expose_denial_reasons: Keyword.get(opts, :expose_denial_reasons, false),
           spec_compliant_errors: Keyword.get(opts, :spec_compliant_errors, false)
         }}

      errors ->
        {:error, errors}
    end
  end

  def build(_), do: {:error, ["options must be a keyword list"]}

  ## Options

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

  defp checks_errors(checks) do
    if is_list(checks) and Enum.all?(checks, &(is_atom(&1) and not is_nil(&1))),
      do: [],
      else: ["`:checks` must be a list of atoms"]
  end

  defp boolean_errors(opts) do
    for key <- [:expose_denial_reasons, :spec_compliant_errors],
        not is_boolean(Keyword.get(opts, key, false)),
        do: "`#{inspect(key)}` must be a boolean"
  end

  ## Hierarchy

  defp hierarchy_errors(hierarchy, role_set) when is_map(hierarchy) do
    Enum.flat_map(hierarchy, fn {role, implied} ->
      hierarchy_key_errors(role, role_set) ++ hierarchy_value_errors(role, implied, role_set)
    end)
  end

  defp hierarchy_errors(_, _role_set), do: ["`:role_hierarchy` must be a map"]

  defp hierarchy_key_errors(role, role_set) do
    if MapSet.member?(role_set, role),
      do: [],
      else: ["`:role_hierarchy` key #{inspect(role)} is not a catalog role"]
  end

  defp hierarchy_value_errors(role, implied, _role_set) when not is_list(implied),
    do: ["`:role_hierarchy` value for #{inspect(role)} must be a list of roles"]

  defp hierarchy_value_errors(role, implied, role_set) do
    for r <- implied, not MapSet.member?(role_set, r) do
      "`:role_hierarchy` #{inspect(role)} implies #{inspect(r)}, which is not a catalog role"
    end
  end

  defp cycle_errors(hierarchy) when is_map(hierarchy) do
    case find_cycle(hierarchy) do
      nil -> []
      cycle -> ["`:role_hierarchy` has a cycle: #{Enum.map_join(cycle, " -> ", &inspect/1)}"]
    end
  end

  defp cycle_errors(_), do: []

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

  ## Role permissions

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
