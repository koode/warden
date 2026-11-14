# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Placeholders do
    @moduledoc false
    # Renumbers the `$n` placeholders of generated SQL, so the SQL can be embedded in a
    # larger raw query that already uses `$1..$offset`: by an offset (`shift/2`), or onto
    # the host's own placeholders where the host binds the same value (`bind/4`).
    #
    # The SQL is lexed as Postgres does, and a `$n` is renumbered only in code: never
    # inside a `--` or nested `/* */` comment, a standard string (`'...''...'`), an
    # escape string (`E'...\'...'`), a dollar-quoted string (`$$...$$`, `$tag$...$tag$`)
    # or a quoted identifier (`"..."""..."`), nor as part of an unquoted identifier
    # (`col$1`). SQL that ends inside any of these raises, because embedded in a host
    # statement it would swallow the host's text. Errors describe the SQL's shape only.

    @unterminated %{
      line_comment: "a line comment",
      block_comment: "a block comment",
      string: "a string literal",
      escape_string: "an escape string literal",
      dollar_quote: "a dollar-quoted string",
      identifier: "a quoted identifier"
    }

    @spec shift(String.t(), non_neg_integer) :: String.t()
    def shift(sql, offset) when is_binary(sql) and is_integer(offset) and offset >= 0 do
      {shifted, _used} = renumber(sql, &(&1 + offset))
      shifted
    end

    # Every param that equals (`===`) a value of `bound` (host placeholder number =>
    # value) becomes that host placeholder, the lowest number when the host binds the
    # value twice, and leaves `params`. The others are numbered from `offset + 1` with no
    # gaps, in their order. Returns the SQL and the params still to pass.
    #
    # The result is checked before it is returned: the placeholders above `offset` must
    # be exactly `offset + 1..offset + length(kept)`, and those at or below it must be
    # keys of `bound`, so a lexing mistake fails closed instead of pointing a scope value
    # at a host parameter.
    @spec bind(String.t(), [term], non_neg_integer, %{pos_integer => term}) ::
            {String.t(), [term]}
    def bind(sql, params, offset, bound)
        when is_binary(sql) and is_list(params) and is_map(bound) do
      hosts = Enum.sort(bound)
      start = {%{}, [], offset + 1}

      {numbers, kept, _next} =
        params
        |> Enum.with_index(1)
        |> Enum.reduce(start, fn {param, number}, acc -> place(hosts, param, number, acc) end)

      {renumbered, used} = renumber(sql, &number!(numbers, &1))
      kept = Enum.reverse(kept)
      verify!(used, offset, length(kept), bound)
      {renumbered, kept}
    end

    defp place(hosts, param, number, {numbers, kept, next}) do
      case Enum.find(hosts, fn {_host, value} -> value === param end) do
        {host, _value} -> {Map.put(numbers, number, host), kept, next}
        nil -> {Map.put(numbers, number, next), [param | kept], next + 1}
      end
    end

    defp number!(numbers, number) do
      case Map.fetch(numbers, number) do
        {:ok, renumbered} -> renumbered
        :error -> raise ArgumentError, "the generated SQL uses a placeholder without a param"
      end
    end

    defp verify!(used, offset, kept_count, bound) do
      {host, own} = used |> Enum.uniq() |> Enum.split_with(&(&1 <= offset))
      expected = Enum.to_list((offset + 1)..(offset + kept_count)//1)
      host? = Enum.all?(host, &(&1 >= 1 and Map.has_key?(bound, &1)))

      if not (host? and Enum.sort(own) == expected) do
        raise ArgumentError, """
        the renumbered SQL does not use exactly its own placeholders \
        #{offset + 1}..#{offset + kept_count} and bound host placeholders\
        """
      end
    end

    # Returns the renumbered SQL and the placeholder numbers it now uses.
    defp renumber(sql, number_for) do
      {iodata, used} = code(sql, number_for, [], [])
      {IO.iodata_to_binary(iodata), used}
    end

    defguardp ident_start?(char)
              when char in ?a..?z or char in ?A..?Z or char == ?_ or char in 0x80..0xFF

    defguardp ident_char?(char) when ident_start?(char) or char in ?0..?9

    defp code(<<>>, _number_for, acc, used), do: {Enum.reverse(acc), used}

    defp code(<<"--", _rest::binary>> = sql, number_for, acc, used),
      do: skip(sql, line_comment_end(sql, 2), :line_comment, number_for, acc, used)

    defp code(<<"/*", _rest::binary>> = sql, number_for, acc, used),
      do: skip(sql, block_comment_end(sql, 2, 1), :block_comment, number_for, acc, used)

    defp code(<<"'", _rest::binary>> = sql, number_for, acc, used),
      do: skip(sql, quoted_end(sql, 1, ?'), :string, number_for, acc, used)

    defp code(<<"\"", _rest::binary>> = sql, number_for, acc, used),
      do: skip(sql, quoted_end(sql, 1, ?"), :identifier, number_for, acc, used)

    defp code(<<"$", digit, _rest::binary>> = sql, number_for, acc, used)
         when digit in ?0..?9 do
      <<"$", rest::binary>> = sql
      {digits, rest} = digits(rest, [])
      number = number_for.(String.to_integer(digits))
      code(rest, number_for, ["$#{number}" | acc], [number | used])
    end

    defp code(<<"$", _rest::binary>> = sql, number_for, acc, used) do
      case dollar_tag(sql, 1) do
        {:ok, delimiter} ->
          size = byte_size(delimiter)
          skip(sql, dollar_quote_end(sql, size, delimiter), :dollar_quote, number_for, acc, used)

        :error ->
          <<dollar, rest::binary>> = sql
          code(rest, number_for, [dollar | acc], used)
      end
    end

    defp code(<<char, _rest::binary>> = sql, number_for, acc, used) when ident_start?(char) do
      size = identifier_end(sql, 1)
      <<identifier::binary-size(^size), rest::binary>> = sql
      escape_string(identifier, rest, number_for, [identifier | acc], used)
    end

    defp code(<<char, rest::binary>>, number_for, acc, used),
      do: code(rest, number_for, [char | acc], used)

    # `E'...'` (or `e'...'`) is an escape string only when the `E` is a token of its own.
    defp escape_string(prefix, <<"'", _rest::binary>> = sql, number_for, acc, used)
         when prefix in ["E", "e"],
         do: skip(sql, escape_string_end(sql, 1), :escape_string, number_for, acc, used)

    defp escape_string(_prefix, rest, number_for, acc, used),
      do: code(rest, number_for, acc, used)

    # Copies the first `size` bytes of `sql` as they are and goes on lexing code after
    # them; `:unterminated` means the SQL ended inside `kind`.
    defp skip(_sql, :unterminated, kind, _number_for, _acc, _used) do
      raise ArgumentError, "the generated SQL ends inside #{Map.fetch!(@unterminated, kind)}"
    end

    defp skip(sql, size, _kind, number_for, acc, used) do
      <<skipped::binary-size(^size), rest::binary>> = sql
      code(rest, number_for, [skipped | acc], used)
    end

    defp line_comment_end(sql, at) when at >= byte_size(sql), do: :unterminated

    defp line_comment_end(sql, at) do
      case :binary.at(sql, at) do
        newline when newline in [?\n, ?\r] -> at + 1
        _other -> line_comment_end(sql, at + 1)
      end
    end

    defp block_comment_end(_sql, at, 0), do: at
    defp block_comment_end(sql, at, _depth) when at >= byte_size(sql), do: :unterminated

    defp block_comment_end(sql, at, depth) do
      case binary_part(sql, at, min(2, byte_size(sql) - at)) do
        "/*" -> block_comment_end(sql, at + 2, depth + 1)
        "*/" -> block_comment_end(sql, at + 2, depth - 1)
        _other -> block_comment_end(sql, at + 1, depth)
      end
    end

    # A standard string or a quoted identifier: the quote doubled stands for itself.
    defp quoted_end(sql, at, _quote) when at >= byte_size(sql), do: :unterminated

    defp quoted_end(sql, at, quote) do
      case binary_part(sql, at, min(2, byte_size(sql) - at)) do
        <<^quote, ^quote>> -> quoted_end(sql, at + 2, quote)
        <<^quote, _next::binary>> -> at + 1
        _other -> quoted_end(sql, at + 1, quote)
      end
    end

    # An escape string: a backslash escapes the next byte, and `''` stands for `'`.
    defp escape_string_end(sql, at) when at >= byte_size(sql), do: :unterminated

    defp escape_string_end(sql, at) do
      case binary_part(sql, at, min(2, byte_size(sql) - at)) do
        <<"\\", _escaped>> -> escape_string_end(sql, at + 2)
        "\\" -> :unterminated
        "''" -> escape_string_end(sql, at + 2)
        <<"'", _next::binary>> -> at + 1
        _other -> escape_string_end(sql, at + 1)
      end
    end

    # `$$` or `$tag$`, where the tag is an identifier without `$`.
    defp dollar_tag(sql, at) when at >= byte_size(sql), do: :error

    defp dollar_tag(sql, at) do
      case :binary.at(sql, at) do
        ?$ -> {:ok, binary_part(sql, 0, at + 1)}
        char when at == 1 and ident_start?(char) -> dollar_tag(sql, at + 1)
        char when at > 1 and ident_char?(char) -> dollar_tag(sql, at + 1)
        _other -> :error
      end
    end

    defp dollar_quote_end(sql, at, delimiter) do
      case :binary.match(sql, delimiter, scope: {at, byte_size(sql) - at}) do
        {start, length} -> start + length
        :nomatch -> :unterminated
      end
    end

    # Unquoted identifiers and keywords may contain digits and `$` after the first byte.
    defp identifier_end(sql, at) when at >= byte_size(sql), do: at

    defp identifier_end(sql, at) do
      case :binary.at(sql, at) do
        char when ident_char?(char) or char == ?$ -> identifier_end(sql, at + 1)
        _other -> at
      end
    end

    defp digits(<<digit, rest::binary>>, acc) when digit in ?0..?9,
      do: digits(rest, [digit | acc])

    defp digits(rest, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}
  end
end
