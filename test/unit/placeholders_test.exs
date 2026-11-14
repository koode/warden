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
end
