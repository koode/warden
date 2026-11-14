defmodule Warden.RedteamMythos.EctoPartialSelectTest do
  # The database side of test/redteam_mythos/ecto_memory_test.exs: a row that scope/4
  # leaves out is granted by the single check and by filter/4 once it was loaded with a
  # partial select. Asserts the secure behaviour, so a failing test is an open hole.
  use Warden.Test.EctoCase, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Ecto.{Issue, Team}

  describe "HOLE goal 8: scope/4 and the checks disagree on a partially selected row" do
    test "a trashed issue of a private team, selected without those columns" do
      team = insert!(%Team{workspace_id: "t1", name: "private", private: true})
      trashed_at = DateTime.truncate(DateTime.utc_now(), :second)

      issue =
        insert!(%Issue{
          workspace_id: "t1",
          team_id: team.id,
          title: "hidden",
          trashed_at: trashed_at
        })

      sam = actor(sam())
      scoped = WardenEcto.scope(Issue, sam, :read)
      assert all_ids(scoped) == []

      query =
        from(row in Issue, where: row.id == ^issue.id, select: [:id, :workspace_id, :title])

      [partial] = Repo.all(query)

      assert WardenEcto.filter(sam, :read, [partial]) == []
      refute WardenEcto.allowed?(sam, :read, partial)
    end
  end
end
