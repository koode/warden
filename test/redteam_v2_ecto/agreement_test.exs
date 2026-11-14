defmodule Warden.RedteamV2Ecto.AgreementTest do
  # Red-team of goal 8: for every row, every actor shape and every policy of the suite,
  # the scope, the single checks (struct, preloaded struct, `{schema, id}`), `filter/3`,
  # `explain/3` and `allowed_actors/3` give the same answer.
  use Warden.Test.EctoCase, async: true

  alias Warden.Credential
  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Ecto.{Authz, Comment, Issue, OauthClient, Project, ProjectMember}
  alias Warden.Test.Ecto.{ProjectTeam, Share, Summary, Team, TeamMembership}

  defp world do
    t1_public = insert!(%Team{workspace_id: "t1", name: "t1 public"})
    t1_private = insert!(%Team{workspace_id: "t1", name: "t1 private", private: true})
    t2_public = insert!(%Team{workspace_id: "t2", name: "t2 public"})
    t2_private = insert!(%Team{workspace_id: "t2", name: "t2 private", private: true})
    insert!(%TeamMembership{team_id: t1_private.id, user_id: "sam"})
    insert!(%TeamMembership{team_id: t2_private.id, user_id: "abby"})

    issues =
      for team <- [t1_public, t1_private, t2_public, t2_private] do
        insert!(%Issue{workspace_id: team.workspace_id, team_id: team.id, author_id: "kim"})
      end

    [i1_public, _i1_private, i2_public, _i2_private] = issues
    teamless = insert!(%Issue{workspace_id: "t1", author_id: "sam"})
    crossing = insert!(%Issue{workspace_id: "t2", team_id: t1_public.id})

    trashed =
      insert!(%Issue{
        workspace_id: "t1",
        team_id: t1_public.id,
        trashed_at: ~U[2026-01-01 00:00:00Z]
      })

    _orphan = insert!(%Issue{workspace_id: nil, team_id: t1_public.id})
    now = NaiveDateTime.truncate(NaiveDateTime.utc_now(), :second)
    expired = NaiveDateTime.add(now, -3600)
    insert!(%Share{issue_id: i2_public.id, grantee_id: "sam"})
    insert!(%Share{issue_id: crossing.id, grantee_id: "sam", expires_at: expired})

    for issue <- [i1_public, i2_public, teamless, crossing, trashed] do
      insert!(%Comment{workspace_id: issue.workspace_id, issue_id: issue.id, author_id: "abby"})
    end

    insert!(%Comment{workspace_id: "t2", issue_id: i1_public.id})
    project = insert!(%Project{workspace_id: "t1", lead_id: "olivia"})
    linked = insert!(%Project{workspace_id: "t1"})
    insert!(%ProjectTeam{project_id: linked.id, team_id: t1_private.id})
    insert!(%ProjectTeam{project_id: project.id, team_id: t2_public.id})
    insert!(%ProjectMember{project_id: linked.id, user_id: "abby"})

    for {type, id} <-
          [{"team", t1_public.id}, {"team", t2_public.id}, {"project", linked.id}] ++
            [{"Team", t1_public.id}, {"issue", i1_public.id}] do
      insert!(%Summary{workspace_id: "t1", subject_type: type, subject_id: id})
    end

    insert!(%OauthClient{workspace_id: nil, owner_id: "sam"})
    insert!(%OauthClient{workspace_id: "t1", owner_id: "kim"})
    :ok
  end

  defp actors do
    bound = %Credential{method: :api_key, tenant: "t1", scopes: ["issues:read"]}
    teams_query = from(team in Team, select: team.id)
    teams = Repo.all(teams_query)

    [
      {"abby", actor(abby())},
      {"sam", actor(sam())},
      {"kim", actor(kim())},
      {"olivia", actor(olivia())},
      {"sam bound to t1", actor(sam(), %{credential: bound})},
      {"webhook t1", webhook(tenant: "t1", bounds: %{team_ids: teams})},
      {"olivia for abby", Warden.on_behalf_of(actor(olivia()), actor(abby()))},
      {"sam for abby", Warden.on_behalf_of(actor(sam()), actor(abby()))},
      {"anonymous", Warden.actor(%{current_user: nil}, authorizer: Authz)}
    ]
  end

  @schemas [
    {Team, :read, []},
    {Issue, :read, [:team]},
    {Issue, :write, [:team]},
    {Comment, :read, [issue: :team]},
    {Project, :read, [:teams, :project_teams]},
    {Summary, :read, []},
    {OauthClient, :read, []}
  ]

  test "scope, checks, filter, explain and allowed_actors agree on every row" do
    :ok = world()
    named_actors = actors()

    for {schema, action, preloads} <- @schemas, {name, actor} <- named_actors do
      scoped = schema |> WardenEcto.scope(actor, action) |> all_ids()
      rows_query = from(row in schema, order_by: row.id)
      rows = Repo.all(rows_query)
      preloaded = Repo.preload(rows, preloads)

      for {row, loaded} <- Enum.zip(rows, preloaded) do
        expected = row.id in scoped
        label = "#{name} #{inspect(schema)} #{action} #{row.id}"
        assert WardenEcto.allowed?(actor, action, row) == expected, "struct: " <> label
        assert WardenEcto.allowed?(actor, action, loaded) == expected, "preloaded: " <> label
        assert WardenEcto.allowed?(actor, action, {schema, row.id}) == expected, "id: " <> label

        explained = WardenEcto.explain(actor, action, row).result == :ok
        assert explained == expected, "explain: " <> label

        audience = WardenEcto.allowed_actors([actor], action, row)
        assert audience == [actor] == expected, "allowed_actors: " <> label
      end

      filtered = actor |> WardenEcto.filter(action, preloaded) |> ids() |> Enum.sort()
      assert filtered == scoped, "filter: #{name} #{inspect(schema)} #{action}"
    end
  end
end
