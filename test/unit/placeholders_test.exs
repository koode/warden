defmodule Warden.Ecto.PlaceholdersTest do
  use ExUnit.Case, async: true

  alias Warden.Ecto.Placeholders

  test "renumbers placeholders from the offset" do
    sql = ~S|SELECT 1 FROM "issues" AS i0 WHERE (i0."workspace_id" = $1) AND (i0."id" = ANY($2))|

    assert Placeholders.shift(sql, 3) ==
             ~S|SELECT 1 FROM "issues" AS i0 WHERE (i0."workspace_id" = $4) AND (i0."id" = ANY($5))|

    assert Placeholders.shift(sql, 0) == sql
  end

  test "leaves string literals and quoted identifiers alone" do
    sql = ~S|SELECT 'costs $1 ''or $2''' AS "col$3" FROM t WHERE x = $1 AND y = $10|

    assert Placeholders.shift(sql, 2) ==
             ~S|SELECT 'costs $1 ''or $2''' AS "col$3" FROM t WHERE x = $3 AND y = $12|
  end

  describe "lexing" do
    test "leaves line comments alone, up to the end of the line" do
      sql = "SELECT 1 WHERE a = $1 -- the author's $1\n AND b = $2 --\r AND c = $3"

      assert Placeholders.shift(sql, 2) ==
               "SELECT 1 WHERE a = $3 -- the author's $1\n AND b = $4 --\r AND c = $5"
    end

    test "leaves block comments alone, nested ones included" do
      sql = "SELECT 1 /* it's $1 /* a nested 'one $2 */ still $3 */ WHERE a = $1 /**/ AND b = $2"

      assert Placeholders.shift(sql, 1) ==
               "SELECT 1 /* it's $1 /* a nested 'one $2 */ still $3 */ WHERE a = $2 /**/ AND b = $3"
    end

    test "leaves dollar-quoted strings alone, with or without a tag" do
      sql = "SELECT $$it's $1$$, $tag$ $$ 'x $2 $tag$, $_t1$$3$_t1$ WHERE a = $1"

      assert Placeholders.shift(sql, 3) ==
               "SELECT $$it's $1$$, $tag$ $$ 'x $2 $tag$, $_t1$$3$_t1$ WHERE a = $4"
    end

    test "leaves escape strings alone, with backslash escapes and doubled quotes" do
      sql = ~S"SELECT E'it\'s $1', e'a\\', e'b''$2\'' WHERE a = $1 AND b = $2"

      assert Placeholders.shift(sql, 1) ==
               ~S"SELECT E'it\'s $1', e'a\\', e'b''$2\'' WHERE a = $2 AND b = $3"
    end

    test "a backslash ends no standard string and starts no escape string in an identifier" do
      sql = ~S"SELECT 'a\', xe'b\' WHERE a = $1"
      assert Placeholders.shift(sql, 1) == ~S"SELECT 'a\', xe'b\' WHERE a = $2"
    end

    test "leaves quoted identifiers alone, with doubled quotes" do
      sql = ~S|SELECT "a""$1'" FROM t WHERE x = $1|
      assert Placeholders.shift(sql, 1) == ~S|SELECT "a""$1'" FROM t WHERE x = $2|
    end

    test "a `$n` inside an unquoted identifier is not a placeholder" do
      sql = "SELECT col$1, x$$ FROM t WHERE a = $1"
      assert Placeholders.shift(sql, 1) == "SELECT col$1, x$$ FROM t WHERE a = $2"
    end

    test "a lone dollar sign is copied" do
      assert Placeholders.shift("SELECT $ + $1", 1) == "SELECT $ + $2"
    end

    test "SQL that ends inside a string, comment, dollar quote or identifier raises" do
      for sql <- [
            "SELECT 'it''s",
            ~S|SELECT E'it\'s|,
            "SELECT E'it\\",
            "SELECT \"col",
            "SELECT $tag$ x $tag",
            "SELECT $$ x",
            "SELECT 1 /* a /* nested */",
            "SELECT 1 -- a comment"
          ] do
        error = assert_raise ArgumentError, fn -> Placeholders.shift(sql, 1) end
        refute Exception.message(error) =~ "SELECT"
      end
    end
  end

  describe "bind/4 checks the result" do
    test "a placeholder without a param raises" do
      assert_raise ArgumentError, fn -> Placeholders.bind("SELECT $1, $2", ["t1"], 1, %{}) end
    end

    test "a param the SQL does not use raises" do
      assert_raise ArgumentError, fn ->
        Placeholders.bind("SELECT 1 -- $1\n", ["t1"], 1, %{})
      end
    end
  end

  describe "bind/4" do
    @sql ~S|SELECT 1 FROM "issues" AS i0 WHERE (i0."workspace_id" = $1) AND (i0."author_id" = $2) AND (i0."team_id" = ANY($3))|

    test "a param the host binds uses the host's placeholder; the others follow the offset" do
      {sql, params} = Placeholders.bind(@sql, ["t1", "sam", [7, 8]], 2, %{1 => "t1", 2 => "sam"})

      assert sql ==
               ~S|SELECT 1 FROM "issues" AS i0 WHERE (i0."workspace_id" = $1) AND (i0."author_id" = $2) AND (i0."team_id" = ANY($3))|

      assert params == [[7, 8]]

      {sql, params} = Placeholders.bind(@sql, ["t1", "sam", [7, 8]], 3, %{2 => "sam"})

      assert sql ==
               ~S|SELECT 1 FROM "issues" AS i0 WHERE (i0."workspace_id" = $4) AND (i0."author_id" = $2) AND (i0."team_id" = ANY($5))|

      assert params == ["t1", [7, 8]]
    end

    test "a value the scope uses twice, or the host binds twice, maps to one placeholder" do
      sql = ~S|SELECT 1 WHERE a = $1 AND b = $2 AND c = $3|

      assert Placeholders.bind(sql, ["t1", 5, "t1"], 1, %{1 => "t1"}) ==
               {~S|SELECT 1 WHERE a = $1 AND b = $2 AND c = $1|, [5]}

      assert Placeholders.bind(sql, ["t1", 5, "t1"], 3, %{3 => "t1", 2 => "t1"}) ==
               {~S|SELECT 1 WHERE a = $2 AND b = $4 AND c = $2|, [5]}
    end

    test "no match leaves the params as they are and only shifts" do
      params = ["t1", "sam", [7, 8]]
      # Only identical values match: not 1.0 for 1, nor a list with a float in it.
      bound = %{1 => "t2", 2 => "sam" <> <<0>>, 3 => [7.0, 8]}

      assert Placeholders.bind(@sql, params, 3, bound) == {Placeholders.shift(@sql, 3), params}

      assert Placeholders.bind(@sql, [1, 2, 3], 1, %{1 => 1.0}) ==
               {Placeholders.shift(@sql, 1), [1, 2, 3]}

      assert Placeholders.bind(@sql, params, 0, %{}) == {@sql, params}
    end

    test "leaves string literals and quoted identifiers alone" do
      sql = ~S|SELECT '$1 ''$2''' AS "col$1" FROM t WHERE x = $1 AND y = $2|

      assert Placeholders.bind(sql, ["t1", "sam"], 1, %{1 => "sam"}) ==
               {~S|SELECT '$1 ''$2''' AS "col$1" FROM t WHERE x = $2 AND y = $1|, ["t1"]}
    end
  end
end
