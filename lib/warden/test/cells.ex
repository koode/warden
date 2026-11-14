defmodule Warden.Test.Cells do
  @moduledoc false
  # Names and messages shared by the test helpers. Names are fixture names or positions,
  # never values, so failure messages never show a subject or row data.

  # Names every entry: `{name, value}` stays, a bare value gets "<label> <position>".
  @spec named(list, String.t()) :: [{atom | String.t(), term}]
  def named(entries, label) do
    entries
    |> Enum.with_index(1)
    |> Enum.map(fn
      {{name, value}, _position} when is_atom(name) -> {name, value}
      {value, position} -> {"#{label} #{position}", value}
    end)
  end

  @spec describe({term, term, atom}, [{String.t(), boolean}]) :: String.t()
  def describe({actor_name, row_name, action}, answer) do
    {allowing, denying} = Enum.split_with(answer, &elem(&1, 1))
    allows = Enum.map_join(allowing, ", ", &elem(&1, 0))
    denies = Enum.map_join(denying, ", ", &elem(&1, 0))
    "#{cell(actor_name, row_name)}, action #{inspect(action)}: #{allows} allow; #{denies} deny"
  end

  @spec cell(atom | String.t(), atom | String.t()) :: String.t()
  def cell(actor_name, row_name), do: "actor #{name(actor_name)}, resource #{name(row_name)}"

  @spec name(atom | String.t()) :: String.t()
  def name(name) when is_atom(name), do: Atom.to_string(name)
  def name(name) when is_binary(name), do: name
end
