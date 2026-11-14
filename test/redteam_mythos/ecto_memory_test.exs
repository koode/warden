defmodule Warden.RedteamMythos.EctoMemoryTest do
  # Red-team of the in-memory decisions of Warden.Ecto. These tests need no database: the
  # test repo is not started here, so a decision that asks the database raises, and only a
  # decision made from the struct alone returns. Every test asserts the secure behaviour.
  use ExUnit.Case, async: true

  import Warden.Test.Ecto.People

  alias Warden.Credential
  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Ecto.{Comment, Issue}

  # `true` only when Warden granted from the struct alone. A denial, and a decision that
  # went to the database (which is not running in this suite), are both `false`.
  defp granted_without_database?(fun) do
    fun.() == true
  rescue
    _repo_not_started in [RuntimeError, ArgumentError, DBConnection.ConnectionError] -> false
  end

  # What `from(issue in Issue, select: [:id, :workspace_id, :title])` returns for a
  # trashed issue of a private team: the columns that were not selected are `nil`.
  defp partial_issue do
    %Issue{id: 41, workspace_id: "t1", title: "trashed, in a private team"}
    |> Map.put(:team_id, nil)
    |> Map.put(:trashed_at, nil)
    |> Map.put(:author_id, nil)
  end

  describe "HOLE goal 8: a struct loaded with a partial select is granted in memory" do
    test "read: an unselected foreign key and trashed_at do not read as NULL columns" do
      sam = actor(sam())

      refute granted_without_database?(fn ->
               WardenEcto.allowed?(sam, :read, partial_issue())
             end),
             """
             the issue was selected without team_id and trashed_at; Warden read the missing \
             columns as NULL (`if_nil: :tenant`, `where: [trashed_at: nil]`) and granted \
             without asking the database, where scope/4 would leave the row out\
             """
    end

    test "filter/4 keeps a partially selected row without asking the database" do
      sam = actor(sam())

      refute granted_without_database?(fn ->
               WardenEcto.filter(sam, :read, [partial_issue()]) != []
             end)
    end

    test "write: an unselected trashed_at lets the author write a trashed issue" do
      key = %Credential{method: :api_key, scopes: ["issues:write"], tenant: nil}
      sam = actor(sam(), %{credential: key})
      selected = %{partial_issue() | author_id: "sam"}

      refute granted_without_database?(fn -> WardenEcto.allowed?(sam, :write, selected) end)
    end

    test "a comment whose preloaded issue was partially selected is not granted through it" do
      sam = actor(sam())
      issue = partial_issue()
      comment = %Comment{id: 7, workspace_id: "t1", issue_id: issue.id, issue: issue}

      refute granted_without_database?(fn -> WardenEcto.allowed?(sam, :read, comment) end)
    end
  end

  describe "held: in-memory decisions that do not depend on missing columns" do
    test "a struct without an id, of another tenant or of another schema is denied" do
      sam = actor(sam())

      refute WardenEcto.allowed?(sam, :read, %{partial_issue() | id: nil})
      refute WardenEcto.allowed?(sam, :read, %{partial_issue() | workspace_id: "t2"})
      refute WardenEcto.allowed?(sam, :read, %{partial_issue() | workspace_id: nil})
    end

    test "a bound credential is denied in memory for a struct of another tenant" do
      key = %Credential{method: :api_key, scopes: :all, tenant: "t2"}
      abby = actor(abby(), %{credential: key})

      refute WardenEcto.allowed?(abby, :read, partial_issue())
    end

    test "an anonymous context and a system actor of another kind are denied in memory" do
      job = Warden.system_actor(Warden.Test.Ecto.Authz, kind: :job, tenant: "t1")

      refute WardenEcto.allowed?(%{}, :read, partial_issue(), authorizer: Warden.Test.Ecto.Authz)
      refute WardenEcto.allowed?(job, :read, partial_issue())
    end

    test "an agent on behalf of a member needs both sides, in memory too" do
      agent = actor(olivia())
      member = actor(sam())
      delegated = Warden.on_behalf_of(agent, member, bounds: %{issue_ids: [99]})
      issue = %{partial_issue() | id: 41}

      refute granted_without_database?(fn ->
               WardenEcto.allowed?(delegated, :read, %{issue | trashed_at: DateTime.utc_now()})
             end)
    end
  end
end
