# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Placeholders do
    @moduledoc false
    # Renumbers the `$n` placeholders of generated SQL, so the SQL can be embedded in a
    # larger raw query that already uses `$1..$offset`: by an offset (`shift/2`), or onto
    # the host's own placeholders where the host binds the same value (`bind/4`). Text
    # inside single quotes (string literals) and double quotes (identifiers) is left
    # alone.

    @spec shift(String.t(), non_neg_integer) :: String.t()
    def shift(sql, 0), do: sql

    def shift(sql, offset) when is_binary(sql) and is_integer(offset) and offset > 0,
      do: renumber(sql, &(&1 + offset))

    # Every param that equals (`===`) a value of `bound` (host placeholder number =>
    # value) becomes that host placeholder, the lowest number when the host binds the
    # value twice, and leaves `params`. The others are numbered from `offset + 1` with no
    # gaps, in their order. Returns the SQL and the params still to pass.
    @spec bind(String.t(), [term], non_neg_integer, %{pos_integer => term}) ::
            {String.t(), [term]}
    def bind(sql, params, offset, bound) when map_size(bound) == 0,
      do: {shift(sql, offset), params}

    def bind(sql, params, offset, bound) when is_binary(sql) and is_list(params) do
      hosts = Enum.sort(bound)
      start = {%{}, [], offset + 1}

      {numbers, kept, _next} =
        params
        |> Enum.with_index(1)
        |> Enum.reduce(start, fn {param, number}, acc -> place(hosts, param, number, acc) end)

      renumbered = renumber(sql, &Map.fetch!(numbers, &1))
      {renumbered, Enum.reverse(kept)}
    end

    defp place(hosts, param, number, {numbers, kept, next}) do
      case Enum.find(hosts, fn {_host, value} -> value === param end) do
        {host, _value} -> {Map.put(numbers, number, host), kept, next}
        nil -> {Map.put(numbers, number, next), [param | kept], next + 1}
      end
    end

    defp renumber(sql, number_for) do
      sql
      |> walk(number_for, :code, [])
      |> IO.iodata_to_binary()
    end

    defp walk(<<>>, _number_for, _state, acc), do: Enum.reverse(acc)

    defp walk(<<"'", rest::binary>>, number_for, :code, acc),
      do: walk(rest, number_for, :single, ["'" | acc])

    defp walk(<<"\"", rest::binary>>, number_for, :code, acc),
      do: walk(rest, number_for, :double, ["\"" | acc])

    defp walk(<<"$", rest::binary>>, number_for, :code, acc) do
      {digits, rest} = digits(rest, [])

      case digits do
        "" ->
          walk(rest, number_for, :code, ["$" | acc])

        number ->
          placeholder = "$#{number_for.(String.to_integer(number))}"
          walk(rest, number_for, :code, [placeholder | acc])
      end
    end

    defp walk(<<"''", rest::binary>>, number_for, :single, acc),
      do: walk(rest, number_for, :single, ["''" | acc])

    defp walk(<<"'", rest::binary>>, number_for, :single, acc),
      do: walk(rest, number_for, :code, ["'" | acc])

    defp walk(<<"\"\"", rest::binary>>, number_for, :double, acc),
      do: walk(rest, number_for, :double, ["\"\"" | acc])

    defp walk(<<"\"", rest::binary>>, number_for, :double, acc),
      do: walk(rest, number_for, :code, ["\"" | acc])

    defp walk(<<char, rest::binary>>, number_for, state, acc),
      do: walk(rest, number_for, state, [char | acc])

    defp digits(<<digit, rest::binary>>, acc) when digit in ?0..?9,
      do: digits(rest, [digit | acc])

    defp digits(rest, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}
  end
end
