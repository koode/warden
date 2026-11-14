defmodule Warden.Ecto.MatrixTest do
  # The policy matrix of the Ecto suite: every policy of the authorizer against owners,
  # members, outsiders, guests, an API key, a delegated agent and a webhook. The snapshot
  # is rewritten with `mix warden.matrix --update`.
  use Warden.Test.Matrix,
    authorizer: Warden.Test.Ecto.Authz,
    repo: Warden.Test.Repo,
    snapshot: "test/ecto/matrix.snapshot"

  import Warden.Test.Ecto.People,
    only: [abby: 0, sam: 0, kim: 0, olivia: 0, context: 1, context: 2, webhook: 1]

  alias Warden.Test.Absinthe, as: AbsintheMatrix
  alias Warden.Test.Ecto.People

  alias Warden.Test.Ecto.{
    Comment,
    Issue,
    Note,
    OauthClient,
    Project,
    Summary,
    Team,
    TeamMembership
  }

  alias Warden.Test.Repo

  @moduletag :postgres

  resource(:team_public, fn _context ->
    Repo.insert!(%Team{workspace_id: "t1", name: "public"})
  end)

  resource(:team_private, fn _context ->
    team = Repo.insert!(%Team{workspace_id: "t1", name: "private", private: true})
    Repo.insert!(%TeamMembership{team_id: team.id, user_id: "sam"})
    team
  end)

  resource :issue_public, &issue(&1, :team_public)
  resource :issue_private, &issue(&1, :team_private)
  resource :issue_teamless, &issue(&1, nil)

  resource(:issue_trashed, fn %{warden_fixtures: fixtures} ->
    Repo.insert!(%Issue{
      workspace_id: "t1",
      team_id: fixtures.team_public.id,
      trashed_at: ~U[2026-01-01 00:00:00Z]
    })
  end)

  resource(:comment_teamless, fn %{warden_fixtures: fixtures} ->
    Repo.insert!(%Comment{
      workspace_id: "t1",
      issue_id: fixtures.issue_teamless.id,
      body: "private words"
    })
  end)

  resource :project_teamless, fn _context -> Repo.insert!(%Project{workspace_id: "t1"}) end

  resource(:summary_team, fn %{warden_fixtures: fixtures} ->
    Repo.insert!(%Summary{
      workspace_id: "t1",
      subject_type: "team",
      subject_id: fixtures.team_public.id
    })
  end)

  resource(:client_t1, fn _context -> Repo.insert!(%OauthClient{workspace_id: "t1"}) end)

  resource(:note_secret, fn _context ->
    Repo.insert!(%Note{workspace_id: "t1", author_id: "abby", secret: true})
  end)

  actor :owner, fn _context -> context(abby()) end
  actor :member, fn _context -> context(sam()) end
  actor :outsider, fn _context -> context(kim()) end
  actor :guest, fn _context -> context(%{id: "gina", memberships: %{"t1" => [:guest]}}) end

  actor(:api_key_read, fn _context ->
    context(sam(), %{credential: %Warden.Credential{method: :api_key, scopes: ["issues:read"]}})
  end)

  actor(:agent, fn %{warden_fixtures: fixtures} ->
    bounds = %{issue_ids: [fixtures.issue_public.id]}
    Warden.on_behalf_of(People.actor(olivia()), People.actor(abby()), bounds: bounds)
  end)

  actor(:webhook, fn %{warden_fixtures: fixtures} ->
    webhook(tenant: "t1", bounds: %{team_ids: [fixtures.team_private.id]})
  end)

  defp issue(%{warden_fixtures: fixtures}, team) do
    team_id = if team, do: Map.fetch!(fixtures, team).id
    Repo.insert!(%Issue{workspace_id: "t1", team_id: team_id, author_id: "kim"})
  end

  test "GraphQL agrees with the policies", %{warden_matrix: matrix} do
    query_for = %{
      issue: "query($id: ID!) { issue(id: $id) { id title } }",
      comment: "query($id: ID!) { comment(id: $id) { id body } }"
    }

    assert AbsintheMatrix.assert_matrix_matches(Warden.Test.Ecto.GraphQL,
             matrix: matrix,
             query_for: query_for
           ) == :ok
  end
end
