defmodule Warden.Ecto.PropertyTest do
  # For random rows and actors, one policy gives one answer everywhere: `allowed?` on a
  # struct (with and without preloads) and on `{schema, id}`, membership in the scope,
  # `filter/4`, and a GraphQL list with a `can/2` object rule.
  use Warden.Test.EctoCase, async: true
  use ExUnitProperties

  alias Warden.Credential
  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Database
  alias Warden.Test.Ecto.{Authz, Comment, Issue, Share, Team, TeamMembership}

  @tenants ["t1", "t2", "t3"]
  @users ["abby", "sam", "kim"]
  @runs 100

  defp world_gen do
    gen all(
          teams <- list_of({member_of(@tenants), boolean()}, min_length: 1, max_length: 5),
          memberships <- list_of({integer(0..4), member_of(@users)}, max_length: 5),
          issues <-
            list_of(
              {member_of([nil | @tenants]), one_of([constant(nil), integer(0..4)]), boolean(),
               member_of([nil | @users])},
              max_length: 8
            ),
          shares <-
            list_of({integer(0..7), member_of(@users), member_of([nil, :past, :future])},
              max_length: 3
            ),
          comments <-
            list_of({member_of(@tenants), one_of([constant(nil), integer(0..7)])}, max_length: 6)
        ) do
      %{
        teams: teams,
        memberships: memberships,
        issues: issues,
        shares: shares,
        comments: comments
      }
    end
  end

  # A tenant role (or none) in every tenant.
  defp memberships_gen do
    roles = member_of([nil, :owner, :admin, :member, :guest])

    gen all(picked <- fixed_list(Enum.map(@tenants, fn _tenant -> roles end))) do
      for {tenant, role} <- Enum.zip(@tenants, picked),
          role != nil,
          into: %{},
          do: {tenant, [role]}
    end
  end

  # `{kind, context}`: a user (maybe with a credential) as a context map, or a built
  # system or delegated actor.
  defp user_gen do
    gen all(
          id <- member_of(@users),
          memberships <- memberships_gen(),
          credential <-
            one_of([
              constant(nil),
              map(member_of(@tenants), &%Credential{method: :api_key, tenant: &1}),
              map(
                list_of(member_of(["issues:read", "issues:write"]), max_length: 2),
                &%Credential{method: :api_key, scopes: &1}
              )
            ])
        ) do
      {:user, %{current_user: %{id: id, memberships: memberships}, credential: credential}}
    end
  end

  defp delegated_gen do
    gen all(
          agent_memberships <- memberships_gen(),
          issue_indexes <- list_of(integer(0..7), max_length: 4),
          {:user, user} <- user_gen()
        ) do
      {:delegated,
       %{agent_memberships: agent_memberships, issue_indexes: issue_indexes, user: user}}
    end
  end

  defp actor_gen do
    webhook =
      gen all(
            tenant <- member_of([nil | @tenants]),
            team_indexes <- list_of(integer(0..4), max_length: 3),
            kind <- member_of([:webhook, :job])
          ) do
        {:system, %{kind: kind, tenant: tenant, team_indexes: team_indexes}}
      end

    one_of([user_gen(), user_gen(), webhook, delegated_gen()])
  end

  defp insert_world!(world) do
    for table <- Database.tables(), do: Repo.query!("DELETE FROM #{table}")

    teams =
      for {tenant, private} <- world.teams,
          do: insert!(%Team{workspace_id: tenant, private: private})

    for {index, user} <- world.memberships, team = Enum.at(teams, index), team != nil do
      insert!(%TeamMembership{team_id: team.id, user_id: user})
    end

    issues = Enum.map(world.issues, &insert_issue!(&1, teams))
    Enum.each(world.shares, &insert_share!(&1, issues))
    Enum.each(world.comments, &insert_comment!(&1, issues))
    %{teams: teams, issues: issues}
  end

  defp insert_issue!({tenant, team_index, trashed, author}, teams) do
    team = team_index && Enum.at(teams, team_index)
    trashed_at = if trashed, do: ~U[2026-01-01 00:00:00Z]
    team_id = team && team.id

    insert!(%Issue{
      workspace_id: tenant,
      team_id: team_id,
      trashed_at: trashed_at,
      author_id: author
    })
  end

  defp insert_share!({index, user, expiry}, issues) do
    case Enum.at(issues, index) do
      nil ->
        :skip

      issue ->
        insert!(%Share{issue_id: issue.id, grantee_id: user, expires_at: expires_at(expiry)})
    end
  end

  defp expires_at(nil), do: nil

  defp expires_at(expiry) do
    now = NaiveDateTime.truncate(NaiveDateTime.utc_now(), :second)
    seconds = if expiry == :past, do: -3600, else: 3600
    NaiveDateTime.add(now, seconds)
  end

  defp insert_comment!({tenant, index}, issues) do
    issue = index && Enum.at(issues, index)
    insert!(%Comment{workspace_id: tenant, issue_id: issue && issue.id})
  end

  defp actor!({:user, context}, _rows), do: {Warden.actor(context, authorizer: Authz), context}

  defp actor!({:system, spec}, rows) do
    team_ids =
      for index <- spec.team_indexes, team = Enum.at(rows.teams, index), team != nil, do: team.id

    actor =
      Warden.system_actor(Authz,
        kind: spec.kind,
        tenant: spec.tenant,
        bounds: %{team_ids: team_ids}
      )

    {actor, nil}
  end

  defp actor!({:delegated, spec}, rows) do
    agent_context = %{
      current_user: %{id: "olivia", kind: :agent, memberships: spec.agent_memberships}
    }

    issue_ids =
      for index <- spec.issue_indexes,
          issue = Enum.at(rows.issues, index),
          issue != nil,
          do: issue.id

    agent = Warden.actor(agent_context, authorizer: Authz)
    user = Warden.actor(spec.user, authorizer: Authz)
    {Warden.on_behalf_of(agent, user, bounds: %{issue_ids: issue_ids}), nil}
  end

  defp scoped(schema, actor, action), do: schema |> WardenEcto.scope(actor, action) |> all_ids()

  defp graphql_ids(context) do
    {:ok, %{data: %{"issues" => issues}}} =
      Absinthe.run("{ issues { id } }", Warden.Test.Ecto.GraphQL, context: context)

    issues |> Enum.map(&String.to_integer(&1["id"])) |> Enum.sort()
  end

  defp assert_one_answer(schema, actor, action, preloads) do
    expected = scoped(schema, actor, action)
    rows = Repo.all(from(row in schema, order_by: row.id))
    preloaded = Repo.preload(rows, preloads)

    for {row, loaded} <- Enum.zip(rows, preloaded) do
      member? = row.id in expected
      assert WardenEcto.allowed?(actor, action, row) == member?
      assert WardenEcto.allowed?(actor, action, loaded) == member?
      assert WardenEcto.allowed?(actor, action, {schema, row.id}) == member?
    end

    assert ids(WardenEcto.filter(actor, action, rows)) == expected
    assert ids(WardenEcto.filter(actor, action, preloaded)) == expected
    expected
  end

  property "allowed? equals membership in the scope equals filter equals a GraphQL list" do
    check all(world <- world_gen(), spec <- actor_gen(), max_runs: @runs) do
      rows = insert_world!(world)
      {actor, context} = actor!(spec, rows)

      for action <- [:read, :read_ids, :read_trashed, :write] do
        expected = assert_one_answer(Issue, actor, action, [:team])

        if action == :read and context != nil do
          assert graphql_ids(context) == expected
        end
      end

      assert_one_answer(Comment, actor, :read, issue: :team)
      assert_one_answer(Team, actor, :read, [])
    end
  end

  property "delegation is never wider than either actor" do
    check all(world <- world_gen(), spec <- delegated_gen(), max_runs: @runs) do
      rows = insert_world!(world)
      {effective, nil} = actor!(spec, rows)

      for {schema, action} <- [
            {Issue, :read},
            {Issue, :read_ids},
            {Issue, :write},
            {Comment, :read},
            {Team, :read}
          ] do
        own = scoped(schema, %{effective | delegator: nil}, action)
        theirs = scoped(schema, effective.delegator, action)
        assert scoped(schema, effective, action) == Enum.filter(own, &(&1 in theirs))
      end
    end
  end

  property "allowed_actors/3 agrees with single checks" do
    check all(
            world <- world_gen(),
            specs <- list_of(actor_gen(), min_length: 1, max_length: 4),
            max_runs: 20
          ) do
      rows = insert_world!(world)
      actors = Enum.map(specs, &(&1 |> actor!(rows) |> elem(0)))

      for issue <- rows.issues, row <- [issue, {Issue, issue.id}] do
        expected = Enum.filter(actors, &WardenEcto.allowed?(&1, :read, row))
        assert WardenEcto.allowed_actors(actors, :read, row) == expected
      end
    end
  end
end
