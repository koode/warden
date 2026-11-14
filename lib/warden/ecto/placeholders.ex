# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Placeholders do
    @moduledoc false
    # Renumbers the `$n` placeholders of generated SQL by an offset, so the SQL can be
    # embedded in a larger raw query that already uses `$1..$offset`. Text inside single
    # quotes (string literals) and double quotes (identifiers) is left alone.

    @spec shift(String.t(), non_neg_integer) :: String.t()
    def shift(sql, 0), do: sql

    def shift(sql, offset) when is_binary(sql) and is_integer(offset) and offset > 0 do
      sql
      |> walk(offset, :code, [])
      |> IO.iodata_to_binary()
    end

    defp walk(<<>>, _offset, _state, acc), do: Enum.reverse(acc)

    defp walk(<<"'", rest::binary>>, offset, :code, acc),
      do: walk(rest, offset, :single, ["'" | acc])

    defp walk(<<"\"", rest::binary>>, offset, :code, acc),
      do: walk(rest, offset, :double, ["\"" | acc])

    defp walk(<<"$", rest::binary>>, offset, :code, acc) do
      {digits, rest} = digits(rest, [])

      case digits do
        "" -> walk(rest, offset, :code, ["$" | acc])
        number -> walk(rest, offset, :code, ["$#{String.to_integer(number) + offset}" | acc])
      end
    end

    defp walk(<<"''", rest::binary>>, offset, :single, acc),
      do: walk(rest, offset, :single, ["''" | acc])

    defp walk(<<"'", rest::binary>>, offset, :single, acc),
      do: walk(rest, offset, :code, ["'" | acc])

    defp walk(<<"\"\"", rest::binary>>, offset, :double, acc),
      do: walk(rest, offset, :double, ["\"\"" | acc])

    defp walk(<<"\"", rest::binary>>, offset, :double, acc),
      do: walk(rest, offset, :code, ["\"" | acc])

    defp walk(<<char, rest::binary>>, offset, state, acc),
      do: walk(rest, offset, state, [char | acc])

    defp digits(<<digit, rest::binary>>, acc) when digit in ?0..?9,
      do: digits(rest, [digit | acc])

    defp digits(rest, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}
  end
end
