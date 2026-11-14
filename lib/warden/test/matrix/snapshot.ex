defmodule Warden.Test.Matrix.Snapshot do
  @moduledoc false
  # The snapshot file of `Warden.Test.Matrix`: a readable table of fixture names, sorted
  # so the same matrix always renders the same text. `cells/1` parses it back into
  # `%{key => value}` so a difference can name the changed cells only:
  #
  #   * `{:actions, policy}` - the policy's actions, space separated;
  #   * `{:cell, resource, actor}` - the allowed actions, comma separated, or "-";
  #   * `{:redacted, resource, actor}` - the redacted fields, comma separated.

  @none "-"

  @header """
  # Warden policy matrix: the actions each actor (column) may take on each resource
  # (row); "-" means none. Fixture names only. Rewrite with `mix warden.matrix --update`.
  """

  @typedoc """
  `policies`: `[{policy, actions, resource_names}]`; `actors`: actor names; `allowed`:
  `%{{resource, actor} => [action]}`; `redacted`: `%{{resource, actor} => [field]}`.
  """
  @type model :: %{
          policies: [{module, [atom], [atom]}],
          actors: [atom],
          allowed: %{{atom, atom} => [atom]},
          redacted: %{{atom, atom} => [atom]}
        }

  @spec render(model) :: String.t()
  def render(model) do
    actors = Enum.sort(model.actors)

    policies =
      model.policies
      |> Enum.sort_by(fn {policy, _actions, _resources} -> inspect(policy) end)
      |> Enum.map_join("\n", &policy_section(&1, actors, model.allowed))

    @header <> "\n" <> policies <> redacted_section(model.redacted)
  end

  defp policy_section({policy, actions, resources}, actors, allowed) do
    header = ["resource" | Enum.map(actors, &Atom.to_string/1)]

    rows =
      for resource <- Enum.sort(resources) do
        cells = Enum.map(actors, &cell(Map.get(allowed, {resource, &1}, [])))
        [Atom.to_string(resource) | cells]
      end

    action_names = actions |> Enum.sort() |> Enum.map_join(" ", &Atom.to_string/1)
    "policy #{inspect(policy)}\nactions #{action_names}\n" <> table([header | rows])
  end

  defp cell([]), do: @none
  defp cell(actions), do: actions |> Enum.sort() |> Enum.map_join(",", &Atom.to_string/1)

  defp redacted_section(redacted) when map_size(redacted) == 0, do: ""

  defp redacted_section(redacted) do
    rows =
      for {{resource, actor}, fields} <- Enum.sort(redacted) do
        [Atom.to_string(resource), Atom.to_string(actor), cell(fields)]
      end

    "\nredacted\n" <> table([["resource", "actor", "fields"] | rows])
  end

  # Left-aligned columns, two spaces apart, no trailing spaces.
  defp table(rows) do
    widths =
      rows
      |> Enum.zip_with(& &1)
      |> Enum.map(fn column -> column |> Enum.map(&String.length/1) |> Enum.max() end)

    Enum.map_join(rows, "", fn row ->
      line =
        row
        |> Enum.zip(widths)
        |> Enum.map_join("  ", fn {text, width} -> String.pad_trailing(text, width) end)
        |> String.trim_trailing()

      line <> "\n"
    end)
  end

  @spec cells(String.t()) :: %{term => String.t()}
  def cells(text) do
    text
    |> String.split("\n")
    |> Enum.reject(&(String.trim(&1) == "" or String.starts_with?(&1, "#")))
    |> Enum.map(&String.split/1)
    |> Enum.reduce({%{}, nil, []}, &parse_line/2)
    |> elem(0)
  end

  defp parse_line(["policy", policy], {cells, _section, _columns}),
    do: {cells, {:policy, policy}, []}

  defp parse_line(["redacted"], {cells, _section, _columns}), do: {cells, :redacted, []}

  defp parse_line(["actions" | actions], {cells, {:policy, policy}, columns}),
    do: {Map.put(cells, {:actions, policy}, Enum.join(actions, " ")), {:policy, policy}, columns}

  defp parse_line(["resource" | columns], {cells, section, _columns}),
    do: {cells, section, columns}

  defp parse_line([resource, actor, fields], {cells, :redacted, columns}),
    do: {Map.put(cells, {:redacted, resource, actor}, fields), :redacted, columns}

  defp parse_line([resource | values], {cells, {:policy, _policy} = section, columns}) do
    cells =
      columns
      |> Enum.zip(values)
      |> Enum.reduce(cells, fn {actor, value}, acc ->
        Map.put(acc, {:cell, resource, actor}, value)
      end)

    {cells, section, columns}
  end

  defp parse_line(_unknown, acc), do: acc

  # One line per cell that differs, sorted.
  @spec diff(map, map) :: [String.t()]
  def diff(snapshot, current) do
    snapshot
    |> Map.keys()
    |> Enum.concat(Map.keys(current))
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.flat_map(fn key ->
      before = Map.get(snapshot, key)
      now = Map.get(current, key)
      if before == now, do: [], else: [describe(key, before, now)]
    end)
  end

  defp describe({:actions, policy}, before, now),
    do: "policy #{policy} actions: snapshot #{shown(before)}, now #{shown(now)}"

  defp describe({:cell, resource, actor}, before, now),
    do: "resource #{resource}, actor #{actor}: snapshot #{shown(before)}, now #{shown(now)}"

  defp describe({:redacted, resource, actor}, before, now) do
    "resource #{resource}, actor #{actor} redacted fields: snapshot #{fields(before)}, now #{fields(now)}"
  end

  defp shown(nil), do: "(not in the matrix)"
  defp shown(value), do: value

  defp fields(nil), do: "none"
  defp fields(value), do: value
end
