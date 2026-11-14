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
