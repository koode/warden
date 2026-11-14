defmodule Warden.Ecto.ScopeTest do
  use Warden.Test.EctoCase, async: true

  import Warden.Test.CompileHelpers, only: [compile!: 1, unique: 1]

  alias Warden.Credential
  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Decisions
  alias Warden.Test.Ecto.{Authz, Comment, Issue, Note, OauthClient, Project, ProjectMember}
  alias Warden.Test.Ecto.{ProjectTeam, Share, Summary, Team, TeamMembership}

  # Teams: t1 public, t1 private (Sam is in it), t2 public, t2 private (Abby is in it),
  # t3 public. One issue per team, plus a t1 issue without a team and a trashed one.
  defp world do
    t1_public = insert!(%Team{workspace_id: "t1", name: "t1 public"})
    t1_private = insert!(%Team{workspace_id: "t1", name: "t1 private", private: true})
    t2_public = insert!(%Team{workspace_id: "t2", name: "t2 public"})
    t2_private = insert!(%Team{workspace_id: "t2", name: "t2 private", private: true})
    t3_public = insert!(%Team{workspace_id: "t3", name: "t3 public"})
    insert!(%TeamMembership{team_id: t1_private.id, user_id: "sam"})
    insert!(%TeamMembership{team_id: t2_private.id, user_id: "abby"})

    issues =
      for team <- [t1_public, t1_private, t2_public, t2_private, t3_public] do
        insert!(%Issue{workspace_id: team.workspace_id, team_id: team.id, title: team.name})
      end

    teamless = insert!(%Issue{workspace_id: "t1", title: "no team", author_id: "kim"})

    trashed =
      insert!(%Issue{
        workspace_id: "t1",
        team_id: t1_public.id,
        trashed_at: ~U[2026-01-01 00:00:00Z]
      })

    [i1_public, i1_private, i2_public, i2_private, i3_public] = issues

    %{
      t1_public: t1_public,
      t1_private: t1_private,
      t2_public: t2_public,
      t2_private: t2_private,
      t3_public: t3_public,
      i1_public: i1_public,
      i1_private: i1_private,
      i2_public: i2_public,
      i2_private: i2_private,
      i3_public: i3_public,
      teamless: teamless,
      trashed: trashed
    }
  end

  defp scope_ids(queryable, actor_or_context, action, opts \\ []) do
    queryable |> WardenEcto.scope(actor_or_context, action, opts) |> all_ids()
  end

  defp sorted_ids(structs), do: structs |> ids() |> Enum.sort()

  # Every row of `schema` is allowed (as a struct with and without `preloads`, and by id)
  # exactly when the scope returns it.
  defp assert_agrees(schema, actor, action, preloads \\ []) do
    scoped = scope_ids(schema, actor, action)
    rows = Repo.all(from(row in schema, order_by: row.id))
    preloaded = Repo.preload(rows, preloads)

    for {row, loaded} <- Enum.zip(rows, preloaded) do
      expected = row.id in scoped
      assert WardenEcto.allowed?(actor, action, row) == expected, "struct #{row.id}"
      assert WardenEcto.allowed?(actor, action, loaded) == expected, "preloaded #{row.id}"
      assert WardenEcto.allowed?(actor, action, {schema, row.id}) == expected, "id #{row.id}"
    end

    assert sorted_ids(WardenEcto.filter(actor, action, rows)) == scoped
    assert sorted_ids(WardenEcto.filter(actor, action, preloaded)) == scoped
    scoped
  end

  describe "tenants" do
    test "scope/3 ORs the scopes of every tenant of the actor" do
      world = world()
      abby = context(abby())

      # Abby: owner of t1 (public teams; the private one is Sam's), guest of t2 (only
      # the private team she is in).
      assert scope_ids(Team, abby, :read, authorizer: Authz) ==
               Enum.sort([world.t1_public.id, world.t2_private.id])

      assert scope_ids(Team, abby, :read, authorizer: Authz, tenant: "t2") == [
               world.t2_private.id
             ]

      assert scope_ids(Team, abby, :read, authorizer: Authz, tenant: "t3") == []
      assert_received {:tenants, "abby"}
    end

    test "a tenant the actor is not in adds nothing" do
      world = world()
      user = Map.put(sam(), :extra_tenants, ["t3", "t2"])

      assert scope_ids(Team, actor(user), :read) ==
               Enum.sort([world.t1_public.id, world.t1_private.id])

      assert scope_ids(Issue, actor(user), :read) ==
               Enum.sort([world.i1_public.id, world.i1_private.id, world.teamless.id])
    end

    test "rows with a NULL tenant are visible only when the policy opts in" do
      _world = world()
      own = insert!(%OauthClient{workspace_id: nil, owner_id: "abby"})
      other = insert!(%OauthClient{workspace_id: nil, owner_id: "sam"})
      t1 = insert!(%OauthClient{workspace_id: "t1", owner_id: "kim"})
      orphan = insert!(%Issue{workspace_id: nil, title: "no workspace"})

      assert scope_ids(OauthClient, actor(abby()), :read) == Enum.sort([own.id, t1.id])
      assert scope_ids(OauthClient, actor(abby()), :read, tenant: nil) == [own.id]
      assert scope_ids(OauthClient, actor(sam()), :read) == [other.id]
      assert assert_agrees(OauthClient, actor(abby()), :read) == Enum.sort([own.id, t1.id])

      refute orphan.id in scope_ids(Issue, actor(abby()), :read)
      refute WardenEcto.allowed?(actor(abby()), :read, orphan)
      assert scope_ids(Issue, actor(abby()), :read, tenant: nil) == []
    end

    test "a credential bound to a tenant sees nothing of other tenants" do
      world = world()
      _own = insert!(%OauthClient{workspace_id: nil, owner_id: "abby"})
      key = context(abby(), %{credential: %Credential{method: :api_key, tenant: "t1"}})

      assert scope_ids(Team, key, :read, authorizer: Authz) == [world.t1_public.id]
      assert scope_ids(Team, key, :read, authorizer: Authz, tenant: "t2") == []
      refute WardenEcto.allowed?(key, :read, world.t2_private, authorizer: Authz)
      refute WardenEcto.allowed?(key, :read, {Team, world.t2_private.id}, authorizer: Authz)
      assert scope_ids(OauthClient, key, :read, authorizer: Authz) == []
      refute_received {:tenant_roles, "abby", "t2"}
    end

    test "WardenEcto.scope/4 takes an explicit authorizer and a context map" do
      world = world()
      ids = scope_ids(Team, context(abby()), :read, authorizer: Authz, tenant: "t1")
      assert ids == [world.t1_public.id]
    end
  end

  describe "system actors" do
    test "pass only clauses that name their kind, within their bounds" do
      world = world()
      hook = webhook(tenant: "t1", bounds: %{team_ids: [world.t1_private.id]})

      assert scope_ids(Team, hook, :read) == [world.t1_private.id]
      assert scope_ids(Issue, hook, :read) == [world.i1_private.id]
      assert_agrees(Team, hook, :read)
      assert_agrees(Issue, hook, :read, [:team])
    end

    test "of a kind the policy does not name, unbound, or for a policy without system kinds get nothing" do
      world = world()

      job =
        Warden.system_actor(Authz,
          kind: :job,
          tenant: "t1",
          bounds: %{team_ids: [world.t1_public.id]}
        )

      unbound = webhook(bounds: %{team_ids: [world.t1_public.id]})
      bound = webhook(tenant: "t1", bounds: %{team_ids: [world.t1_public.id]})

      assert scope_ids(Team, job, :read) == []
      assert scope_ids(Team, unbound, :read) == []
      assert scope_ids(Project, bound, :read) == []
      refute WardenEcto.allowed?(job, :read, world.t1_public)
    end
  end

  describe "delegation" do
    test "an agent on behalf of a user sees the AND of both, within the bounds" do
      world = world()
      agent = actor(olivia())
      user = actor(abby())
      bounded = [world.i1_public.id, world.i1_private.id, world.i2_private.id]
      effective = Warden.on_behalf_of(agent, user, bounds: %{issue_ids: bounded})

      agent_ids = scope_ids(Issue, %{effective | delegator: nil}, :read)
      user_ids = scope_ids(Issue, user, :read)
      effective_ids = scope_ids(Issue, effective, :read)

      # Abby may read i1_public and i2_private, but Olivia is only in t1; every member of
      # t1 may read the teamless issue.
      assert effective_ids == Enum.sort([world.i1_public.id, world.teamless.id])
      assert effective_ids == Enum.filter(agent_ids, &(&1 in user_ids))
      assert_agrees(Issue, effective, :read, [:team])
    end

    test "an agent without bounds gets nothing from within:" do
      world = world()
      effective = Warden.on_behalf_of(actor(olivia()), actor(abby()))

      # Only the teamless issue, which every member of t1 may read (`if_nil: :tenant`).
      assert scope_ids(Issue, effective, :read) == [world.teamless.id]
    end
  end

  describe "clauses" do
    test "rule: and where:" do
      world = world()

      assert scope_ids(Team, actor(sam()), :read, tenant: "t1") ==
               Enum.sort([world.t1_public.id, world.t1_private.id])

      assert_agrees(Team, actor(sam()), :read)
      assert_agrees(Team, actor(kim()), :read)
    end

    test "member_of:" do
      world = world()
      guest = actor(%{id: "sam", memberships: %{"t1" => [:guest]}})
      assert scope_ids(Team, guest, :read) == [world.t1_private.id]
      assert_agrees(Team, guest, :read)
    end

    test "through: with if_nil: :tenant, and where: [field: nil]" do
      world = world()
      expected = Enum.sort([world.i1_public.id, world.i1_private.id, world.teamless.id])

      assert assert_agrees(Issue, actor(sam()), :read, [:team]) == expected
      refute world.trashed.id in expected
    end

    test "through: a nil foreign key denies by default" do
      world = world()
      orphan = insert!(%Comment{workspace_id: "t1", issue_id: nil})
      on_issue = insert!(%Comment{workspace_id: "t1", issue_id: world.i1_public.id})

      assert assert_agrees(Comment, actor(sam()), :read, issue: :team) == [on_issue.id]
      refute WardenEcto.allowed?(actor(sam()), :read, orphan)
    end

    test "through: never crosses tenants" do
      world = world()
      # A t2 comment on a t1 issue that Sam may read.
      crossing = insert!(%Comment{workspace_id: "t2", issue_id: world.i1_public.id})
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})

      refute crossing.id in scope_ids(Comment, actor(user), :read)
      assert_agrees(Comment, actor(user), :read, issue: :team)
    end

    test "a three-policy chain agrees with a hand-written join" do
      world = world()

      for issue <- [
            world.i1_public,
            world.i1_private,
            world.i2_public,
            world.teamless,
            world.trashed
          ] do
        insert!(%Comment{workspace_id: issue.workspace_id, issue_id: issue.id})
      end

      for user <- [abby(), sam(), kim()] do
        actor = actor(user)
        id = user.id

        member_tenants =
          for {tenant, roles} <- user.memberships, roles -- [:guest] != [], do: tenant

        tenants = Map.keys(user.memberships)

        joined =
          from(comment in Comment,
            join: issue in Issue,
            on: issue.id == comment.issue_id and issue.workspace_id == comment.workspace_id,
            left_join: team in Team,
            on: team.id == issue.team_id and team.workspace_id == issue.workspace_id,
            left_join: membership in TeamMembership,
            on: membership.team_id == team.id and membership.user_id == ^id,
            where: comment.workspace_id in ^tenants and is_nil(issue.trashed_at),
            where:
              (is_nil(issue.team_id) and issue.workspace_id in ^tenants) or
                (not is_nil(team.id) and
                   ((team.private == false and team.workspace_id in ^member_tenants) or
                      not is_nil(membership.id))),
            select: comment.id,
            distinct: true
          )

        assert scope_ids(Comment, actor, :read) == Enum.sort(Repo.all(joined)), user.id
      end
    end

    test "grant: with expires_at" do
      world = world()
      now = NaiveDateTime.truncate(NaiveDateTime.utc_now(), :second)
      insert!(%Share{issue_id: world.i2_public.id, grantee_id: "sam"})

      insert!(%Share{
        issue_id: world.i3_public.id,
        grantee_id: "sam",
        expires_at: NaiveDateTime.add(now, 3600)
      })

      insert!(%Share{
        issue_id: world.i2_private.id,
        grantee_id: "sam",
        expires_at: NaiveDateTime.add(now, -3600)
      })

      user =
        Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:guest], "t3" => [:guest]})

      ids = assert_agrees(Issue, actor(user), :read, [:team])
      assert world.i2_public.id in ids
      assert world.i3_public.id in ids
      refute world.i2_private.id in ids
    end

    test "actor_in: and requires: credential_scope" do
      world = world()
      kim = Map.put(kim(), :memberships, %{"t1" => [:guest]})
      session = actor(kim)

      read_only =
        actor(kim, %{credential: %Credential{method: :api_key, scopes: ["issues:read"]}})

      assert assert_agrees(Issue, session, :write, [:team]) == [world.teamless.id]
      assert scope_ids(Issue, read_only, :write) == []
      assert_agrees(Issue, actor(sam()), :write, [:team])
    end

    test "none:, through_any: (many_to_many), actor_in: and member_of: on projects" do
      world = world()
      teamless = insert!(%Project{workspace_id: "t1", name: "no team"})
      public = insert!(%Project{workspace_id: "t1", name: "public team"})
      private = insert!(%Project{workspace_id: "t1", name: "private team"})
      led = insert!(%Project{workspace_id: "t1", name: "led", lead_id: "olivia"})
      membered = insert!(%Project{workspace_id: "t1", name: "membered"})
      insert!(%ProjectTeam{project_id: public.id, team_id: world.t1_public.id})
      insert!(%ProjectTeam{project_id: private.id, team_id: world.t1_private.id})
      insert!(%ProjectTeam{project_id: led.id, team_id: world.t1_private.id})
      insert!(%ProjectTeam{project_id: membered.id, team_id: world.t1_private.id})
      insert!(%ProjectMember{project_id: membered.id, user_id: "olivia"})

      sam = assert_agrees(Project, actor(sam()), :read, [:teams, :project_teams])
      assert sam == Enum.sort([teamless.id, public.id, private.id, led.id, membered.id])

      abby = assert_agrees(Project, actor(abby()), :read, [:teams])
      assert abby == Enum.sort([teamless.id, public.id])

      olivia = assert_agrees(Project, actor(olivia()), :read, [:teams])
      assert olivia == Enum.sort([led.id, membered.id])
    end

    test "requires: check(...) runs once per actor, tenant and action per call" do
      _world = world()
      insert!(%Project{workspace_id: "t1"})
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})

      _ids = scope_ids(Project, context(user), :read, authorizer: Authz)
      assert_received {:check, :active}
      assert_received {:check, :active}
      refute_received {:check, :active}

      assert scope_ids(Project, context(user, %{active: false}), :read, authorizer: Authz) == []
    end

    test "through_type: decides by the policy of the row's type; other types deny" do
      world = world()
      project = insert!(%Project{workspace_id: "t1"})
      comment = insert!(%Comment{workspace_id: "t1", issue_id: world.i1_public.id})

      visible =
        for {type, id} <- [
              {"project", project.id},
              {"team", world.t1_public.id},
              {"comment", comment.id}
            ] do
          insert!(%Summary{workspace_id: "t1", subject_type: type, subject_id: id})
        end

      hidden =
        insert!(%Summary{
          workspace_id: "t1",
          subject_type: "team",
          subject_id: world.t2_public.id
        })

      unknown =
        insert!(%Summary{
          workspace_id: "t1",
          subject_type: "pull_request",
          subject_id: world.t1_public.id
        })

      ids = assert_agrees(Summary, actor(sam()), :read)
      assert ids == sorted_ids(visible)
      refute hidden.id in ids
      refute WardenEcto.allowed?(actor(sam()), :read, unknown)
    end

    test "when: returns a dynamic like scope/4" do
      world = world()
      own = insert!(%Comment{workspace_id: "t1", author_id: "abby"})
      other = insert!(%Comment{workspace_id: "t1", author_id: "sam"})
      on_issue = insert!(%Comment{workspace_id: "t1", issue_id: world.i1_public.id})

      ids = assert_agrees(Comment, actor(abby()), :read)
      assert ids == Enum.sort([own.id, on_issue.id])
      refute other.id in ids
    end

    test "a hand-written scope/4 with a matching allowed?/4" do
      _world = world()
      public = insert!(%Note{workspace_id: "t1", author_id: "abby"})
      secret = insert!(%Note{workspace_id: "t1", author_id: "abby", secret: true})
      other = insert!(%Note{workspace_id: "t1", author_id: "kim", secret: true})

      assert assert_agrees(Note, actor(sam()), :read) == [public.id]
      assert assert_agrees(Note, actor(abby()), :read) == Enum.sort([public.id, secret.id])
      assert assert_agrees(Note, actor(abby()), :write) == Enum.sort([public.id, secret.id])
      refute WardenEcto.allowed?(actor(abby()), :write, other)
    end
  end

  describe "single checks and lists" do
    test "loaded structs are decided in memory when the clauses allow it" do
      world = world()

      # `where: [private: false]` on a loaded team is exact in memory.
      {allowed, count} =
        count_queries(fn -> WardenEcto.allowed?(actor(sam()), :read, world.t1_public) end)

      assert allowed
      assert count == 0

      # `where: [trashed_at: nil]` matches a `nil`, which may be an unselected column, so
      # the database decides, even with the team preloaded.
      issue = Repo.preload(world.i1_public, :team)
      {allowed, count} = count_queries(fn -> WardenEcto.allowed?(actor(sam()), :read, issue) end)
      assert allowed
      assert count == 1
    end

    test "a partially selected row is decided by the database" do
      world = world()

      trashed_query =
        from(issue in Issue, where: issue.id == ^world.trashed.id, select: [:id, :workspace_id])

      [partial] = Repo.all(trashed_query)

      refute WardenEcto.allowed?(actor(sam()), :read, partial)
      assert WardenEcto.filter(actor(sam()), :read, [partial]) == []
    end

    test "a hand-written allowed?/4 answers structs; ids go to the database" do
      note = insert!(%Note{workspace_id: "t1", author_id: "abby"})

      {allowed, count} =
        count_queries(fn ->
          WardenEcto.allowed?(context(sam()), :read, note, authorizer: Authz)
        end)

      assert allowed and count == 0
      assert_received {:allowed?, :read, _id}

      {allowed, count} =
        count_queries(fn -> WardenEcto.allowed?(actor(sam()), :read, {Note, note.id}) end)

      assert allowed and count == 1
    end

    test "by id: invalid and unknown ids deny" do
      _world = world()
      refute WardenEcto.allowed?(actor(sam()), :read, {Issue, "not an id"})
      refute WardenEcto.allowed?(actor(sam()), :read, {Issue, -1})
      refute WardenEcto.allowed?(actor(sam()), :read, {Issue, nil})
    end

    test "authorize/4 returns a denial" do
      world = world()
      assert WardenEcto.authorize(actor(sam()), :read, world.i1_public) == :ok

      assert {:error,
              %Warden.Denial{kind: :call, rule: {:can, Warden.Test.Ecto.Issues, :read, []}}} =
               WardenEcto.authorize(actor(sam()), :read, world.i2_public)
    end

    test "filter/4 runs one query per tenant of the actor, keeps the order and duplicates" do
      world = world()
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})

      issues = [
        world.i2_public,
        world.i1_public,
        world.i3_public,
        world.i1_public,
        world.i2_private
      ]

      {filtered, count} = count_queries(fn -> WardenEcto.filter(actor(user), :read, issues) end)
      assert ids(filtered) == [world.i2_public.id, world.i1_public.id, world.i1_public.id]
      assert count == 2
      assert WardenEcto.filter(actor(user), :read, []) == []
    end

    test "filter/4 takes rows of one schema" do
      world = world()

      assert_raise ArgumentError, ~r/rows of one schema/, fn ->
        WardenEcto.filter(actor(sam()), :read, [world.i1_public, world.t1_public])
      end
    end

    test "allowed_actors/4 agrees with single checks in one query" do
      world = world()
      users = [abby(), sam(), kim(), olivia(), Map.put(kim(), :memberships, %{"t1" => [:guest]})]
      contexts = Enum.map(users, &context/1)
      hook = webhook(tenant: "t1", bounds: %{team_ids: [world.t1_private.id]})
      actors = [hook | Enum.map(users, &actor/1)]

      for row <- [
            world.i1_public,
            world.i1_private,
            world.teamless,
            world.trashed,
            {Issue, world.i1_private.id}
          ] do
        expected = Enum.filter(actors, &WardenEcto.allowed?(&1, :read, row))
        {allowed, count} = count_queries(fn -> WardenEcto.allowed_actors(actors, :read, row) end)

        assert allowed == expected
        assert count <= 1

        expected_contexts =
          Enum.filter(contexts, &WardenEcto.allowed?(&1, :read, row, authorizer: Authz))

        assert WardenEcto.allowed_actors(contexts, :read, row, authorizer: Authz) ==
                 expected_contexts
      end
    end

    test "explain/4 reports every clause" do
      world = world()

      explanation = WardenEcto.explain(actor(sam()), :read, world.i1_private)
      assert explanation.result == :ok
      [through, grant, agent, hook] = explanation.steps
      assert %{rule: {:allow, :read, _index}, result: :ok} = through

      assert [
               %{
                 rule: {:through, :team, nil, :tenant, %{resolve: :exists, system: :deny}},
                 result: :ok
               },
               %{rule: {:where, [trashed_at: nil]}, result: :ok}
             ] = through.steps

      assert grant.result == {:deny, nil}
      assert agent.result == {:deny, nil}
      assert hook.result == {:deny, nil}

      trashed = WardenEcto.explain(actor(sam()), :read, {Issue, world.trashed.id})
      assert trashed.result == :deny

      assert [%{result: {:deny, nil}, steps: [%{result: :ok}, %{result: {:deny, nil}}]} | _rest] =
               trashed.steps

      write =
        WardenEcto.explain(
          actor(sam(), %{credential: %Credential{method: :api_key, scopes: []}}),
          :write,
          world.i1_public
        )

      assert write.result == :deny
      assert [%{rule: {:requires, :write, _index}, result: {:deny, nil}} | _rest] = write.steps

      hook = webhook(tenant: "t2", bounds: %{})

      assert %{result: :deny, steps: [%{rule: {:gate, :tenant_binding}}]} =
               WardenEcto.explain(hook, :read, world.i1_public)

      assert %{result: :deny, steps: [%{rule: {:gate, :no_row}}]} =
               WardenEcto.explain(actor(sam()), :read, {Issue, -1})

      note = insert!(%Note{workspace_id: "t1", author_id: "abby"})

      assert %{result: :ok, steps: [%{rule: {:scope, :read}, result: :ok}]} =
               WardenEcto.explain(actor(sam()), :read, note)

      for row <- [world.i1_public, world.i2_public, world.teamless, world.trashed] do
        assert WardenEcto.explain(actor(abby()), :read, row).result ==
                 if(WardenEcto.allowed?(actor(abby()), :read, row), do: :ok, else: :deny)
      end
    end

    test "explain/4 explains the delegator too" do
      world = world()

      effective =
        Warden.on_behalf_of(actor(olivia()), actor(kim()),
          bounds: %{issue_ids: [world.i1_public.id]}
        )

      explanation = WardenEcto.explain(effective, :read, world.i1_public)

      assert explanation.result == :deny
      assert %Warden.Explanation{result: :deny} = explanation.delegator
    end
  end

  describe "writes" do
    test "update_all/4 and delete_all/3 run a write-scoped query" do
      world = world()
      query = WardenEcto.scope(Issue, actor(sam()), :write)
      expected = scope_ids(Issue, actor(sam()), :write)

      assert {count, nil} = WardenEcto.update_all(Repo, query, [set: [title: "edited"]], [])
      assert count == length(expected)
      assert Repo.get!(Issue, world.i1_public.id).title == "edited"
      assert Repo.get!(Issue, world.i2_public.id).title == "t2 public"

      narrowed = where(query, [issue: issue], issue.id == ^world.i1_public.id)
      assert {1, nil} = WardenEcto.delete_all(Repo, narrowed, [])
      assert Repo.get(Issue, world.i1_public.id) == nil
    end
  end

  describe "through options" do
    test "resolve: :ids compares the foreign key with the parent ids, once per tenant" do
      world = world()
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})

      {sql, _params} = WardenEcto.to_sql(Issue, actor(user), :read_ids, [])
      assert sql =~ ~s("team_id" = ANY($)
      refute sql =~ ~s(FROM "teams")

      {_query, count} = count_queries(fn -> WardenEcto.scope(Issue, actor(user), :read_ids) end)
      assert count == 2

      read_ids = assert_agrees(Issue, actor(user), :read_ids, [:team])

      expected =
        Enum.sort([
          world.i1_public.id,
          world.i1_private.id,
          world.teamless.id,
          world.i2_public.id
        ])

      assert read_ids == expected
    end

    test "resolve: :ids keeps the tenant condition" do
      world = world()
      # A t2 issue on a t1 team that Sam may read.
      crossing = insert!(%Issue{workspace_id: "t2", team_id: world.t1_public.id})
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:guest]})

      refute crossing.id in assert_agrees(Issue, actor(user), :read_ids, [:team])
    end

    test "system: :inherit admits the system actors the parent admits, through that clause only" do
      world = world()
      hook = webhook(tenant: "t1", bounds: %{team_ids: [world.t1_private.id]})

      job =
        Warden.system_actor(Authz,
          kind: :job,
          tenant: "t1",
          bounds: %{team_ids: [world.t1_private.id]}
        )

      assert assert_agrees(Issue, hook, :read_ids, [:team]) == [world.i1_private.id]
      assert assert_agrees(Issue, job, :read_ids, [:team]) == []
      assert scope_ids(Issue, job, :read) == []
      assert scope_ids(Issue, job, :write) == []
    end

    test "through_any: with system: :inherit lets the child policy decide system actors" do
      world = world()
      authorizer = unique("Warden.Test.Compiled.InheritAnyAuthz")
      teams = unique("Warden.Test.Compiled.InheritAnyTeams")
      projects = unique("Warden.Test.Compiled.InheritAnyProjects")

      compile!("""
      defmodule #{authorizer} do
        use Warden.Authorizer,
          roles: [:admin],
          kinds: [:user, :webhook, :job],
          tenant_roles: [:member],
          policies: [#{teams}, #{projects}]

        def subject(context), do: context[:current_user]
        def roles(_user, _context), do: []
        def tenant_roles(_user, _tenant, _context), do: [:member]
        def tenants(_actor, _context), do: ["t1"]
      end

      defmodule #{teams} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer}, schema: Warden.Test.Ecto.Team, as: :team,
          tenant: :workspace_id, repo: Warden.Test.Repo, actions: [:read],
          system_kinds: [:webhook]

        allow :read, rule: kind(:webhook), within: {:team_ids, :id}
      end

      defmodule #{projects} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer}, schema: Warden.Test.Ecto.Project, as: :project,
          tenant: :workspace_id, repo: Warden.Test.Repo, actions: [:read],
          system_kinds: [:webhook, :job]

        allow :read, through_any: {:teams, :read, system: :inherit}
      end
      """)

      authorizer = Module.concat([authorizer])
      on_private = insert!(%Project{workspace_id: "t1", name: "private team"})
      on_public = insert!(%Project{workspace_id: "t1", name: "public team"})
      insert!(%ProjectTeam{project_id: on_private.id, team_id: world.t1_private.id})
      insert!(%ProjectTeam{project_id: on_public.id, team_id: world.t1_public.id})
      bounds = %{team_ids: [world.t1_private.id]}
      hook = Warden.system_actor(authorizer, kind: :webhook, tenant: "t1", bounds: bounds)
      job = Warden.system_actor(authorizer, kind: :job, tenant: "t1", bounds: bounds)

      assert assert_agrees(Project, hook, :read, [:teams]) == [on_private.id]
      assert assert_agrees(Project, job, :read, [:teams]) == []
    end

    test "within: with if_missing: :allow admits when the bounds key is missing" do
      world = world()
      authorizer = unique("Warden.Test.Compiled.OptionalLimitAuthz")
      policy = unique("Warden.Test.Compiled.OptionalLimit")

      compile!("""
      defmodule #{authorizer} do
        use Warden.Authorizer, roles: [:admin], tenant_roles: [:member], policies: [#{policy}]
        def subject(context), do: context[:current_user]
        def roles(_user, _context), do: []
        def credential(context), do: context[:credential]
        def tenant_roles(_user, _tenant, _context), do: [:member]
        def tenants(_actor, _context), do: ["t1"]
      end

      defmodule #{policy} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer}, schema: Warden.Test.Ecto.Team, as: :team,
          tenant: :workspace_id, repo: Warden.Test.Repo, actions: [:read]

        allow :read, rule: tenant_role(:member), within: {:team_ids, :id, if_missing: :allow}
      end
      """)

      authorizer = Module.concat([authorizer])
      policy = Module.concat([policy])
      limited = %Warden.Credential{method: :api_key, bounds: %{team_ids: [world.t1_private.id]}}
      empty = %Warden.Credential{method: :api_key, bounds: %{team_ids: []}}

      actors = [
        unlimited: %{current_user: %{id: "sam"}},
        limited: %{current_user: %{id: "sam"}, credential: limited},
        empty: %{current_user: %{id: "sam"}, credential: empty}
      ]

      rows = [public: world.t1_public, private: world.t1_private]
      cells = Warden.Test.assert_policy_consistent(policy, actors, rows, authorizer: authorizer)

      assert cells[{:unlimited, :public, :read}] and cells[{:unlimited, :private, :read}]
      refute cells[{:limited, :public, :read}]
      assert cells[{:limited, :private, :read}]
      refute cells[{:empty, :public, :read}] or cells[{:empty, :private, :read}]
    end

    test "none: over a many_to_many reads the join table only" do
      _world = world()
      {sql, _params} = WardenEcto.to_sql(Project, actor(sam()), :read, tenant: "t1")
      assert sql =~ ~r/NOT \(exists\(\(SELECT 1 FROM "project_teams" AS \w+ WHERE/
    end
  end

  describe "preload_ids/4" do
    alias Warden.Test.Ecto.Teams

    # The cache entries `preload_ids/4` added: the ids, without tenant roles and tenants.
    defp ids_entries(actor) do
      Map.filter(actor.cache, fn {key, _ids} -> is_tuple(key) and elem(key, 0) == :ids end)
    end

    defp with_entries(actor, entries), do: %{actor | cache: Map.merge(actor.cache, entries)}

    test "scopes after preload_ids/4 read the parent ids from the actor" do
      world = world()
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})
      plain = actor(user)

      {preloaded, preload_count} =
        count_queries(fn -> WardenEcto.preload_ids(plain, Team, :read) end)

      assert preload_count == 2

      {_queries, count} =
        count_queries(fn ->
          for tenant <- [[], [tenant: "t1"], [tenant: "t2"]] do
            WardenEcto.scope(Issue, preloaded, :read_ids, tenant)
          end
        end)

      assert count == 0

      {_queries, uncached} =
        count_queries(fn ->
          for _call <- 1..3, do: WardenEcto.scope(Issue, plain, :read_ids, tenant: "t1")
        end)

      assert uncached == 3

      assert scope_ids(Issue, preloaded, :read_ids) == scope_ids(Issue, plain, :read_ids)
      assert world.i1_private.id in scope_ids(Issue, preloaded, :read_ids)
      assert WardenEcto.preload_ids(plain, Teams, :read) == preloaded
    end

    test "another tenant, prefix or action reads the ids again" do
      _world = world()
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})
      preloaded = WardenEcto.preload_ids(actor(user), Team, :read, tenant: "t1")

      count = fn opts ->
        {_query, count} =
          count_queries(fn -> WardenEcto.scope(Issue, preloaded, :read_ids, opts) end)

        count
      end

      assert count.(tenant: "t1") == 0
      assert count.(tenant: "t2") == 1
      assert count.(tenant: "t1", prefix: "public") == 1

      authorizer = unique("Warden.Test.Compiled.IdsActionAuthz")
      teams = unique("Warden.Test.Compiled.IdsActionTeams")
      issues = unique("Warden.Test.Compiled.IdsActionIssues")

      compile!("""
      defmodule #{authorizer} do
        use Warden.Authorizer,
          roles: [:admin],
          tenant_roles: [:member],
          policies: [#{teams}, #{issues}]

        def subject(context), do: context[:current_user]
        def roles(_user, _context), do: []
        def tenant_roles(_user, _tenant, _context), do: [:member]
        def tenants(_actor, _context), do: ["t1"]
      end

      defmodule #{teams} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer}, schema: Warden.Test.Ecto.Team, as: :team,
          tenant: :workspace_id, repo: Warden.Test.Repo, actions: [:read, :manage]

        allow :read, rule: tenant_role(:member)
        allow :manage, rule: tenant_role(:member), where: [private: true]
      end

      defmodule #{issues} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer}, schema: Warden.Test.Ecto.Issue, as: :issue,
          tenant: :workspace_id, repo: Warden.Test.Repo, actions: [:read]

        allow :read, through: {:team, :read, resolve: :ids}
      end
      """)

      authorizer = Module.concat([authorizer])
      member = Warden.actor(%{current_user: %{id: "sam"}}, authorizer: authorizer)
      managed = WardenEcto.preload_ids(member, Team, :manage)
      read = WardenEcto.preload_ids(member, Team, :read)

      {managed_ids, managed_count} = count_queries(fn -> scope_ids(Issue, managed, :read) end)
      {read_ids, read_count} = count_queries(fn -> scope_ids(Issue, read, :read) end)

      assert managed_count == 2
      assert read_count == 1
      assert managed_ids == read_ids
    end

    test "each side of a delegated actor has its own ids, never used for the other" do
      world = world()
      agent = actor(olivia())
      user = actor(abby())
      effective = Warden.on_behalf_of(agent, user)
      preloaded = WardenEcto.preload_ids(effective, Team, :read)

      # Olivia sees no team, so only the teamless issue of t1 (`if_nil: :tenant`).
      expected = scope_ids(Issue, effective, :read_ids)
      assert expected == [world.teamless.id]

      {ids, count} = count_queries(fn -> scope_ids(Issue, preloaded, :read_ids) end)
      assert count == 1
      assert ids == expected

      # The agent's entries in the user's struct and the other way round: both sides read
      # their ids again.
      own = ids_entries(preloaded)
      theirs = ids_entries(preloaded.delegator)
      assert map_size(own) == 1 and map_size(theirs) == 1
      swapped = with_entries(effective, theirs)
      swapped = %{swapped | delegator: with_entries(user, own)}

      {ids, count} = count_queries(fn -> scope_ids(Issue, swapped, :read_ids) end)
      assert count == 3
      assert ids == expected

      # The agent alone decides like the agent's side without delegation bounds, but not
      # like the side narrowed by `bounds:`.
      alone = WardenEcto.preload_ids(agent, Team, :read)
      delegated = Warden.on_behalf_of(alone, user)
      bounded = Warden.on_behalf_of(alone, user, bounds: %{issue_ids: [world.i1_public.id]})

      {_ids, count} = count_queries(fn -> scope_ids(Issue, delegated, :read_ids) end)
      assert count == 2
      {_ids, count} = count_queries(fn -> scope_ids(Issue, bounded, :read_ids) end)
      assert count == 3
    end

    test "assert_policy_consistent/4 agrees for a preloaded actor" do
      world = world()
      user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:guest]})
      plain = actor(user)
      preloaded = WardenEcto.preload_ids(plain, Team, :read)
      rows = [i1_public: world.i1_public, i1_private: world.i1_private, i2: world.i2_public]

      cells =
        Warden.Test.assert_policy_consistent(
          Warden.Test.Ecto.Issues,
          [plain: plain, preloaded: preloaded],
          rows,
          actions: [:read_ids]
        )

      for {row, _struct} <- rows do
        assert cells[{:plain, row, :read_ids}] == cells[{:preloaded, row, :read_ids}]
      end

      assert cells[{:preloaded, :i1_public, :read_ids}]
    end

    test "without a resolve: :ids clause for the parent, reads nothing and warns once" do
      _world = world()
      plain = actor(sam())

      # No policy of the authorizer has `through: ..., resolve: :ids` to issues.
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          {returned, count} = count_queries(fn -> WardenEcto.preload_ids(plain, Issue, :read) end)
          assert returned == plain
          assert count == 0
        end)

      assert log =~ "Warden.Ecto.preload_ids/4 for Warden.Test.Ecto.Issues :read read nothing"
      assert log =~ "resolve: :ids"

      again =
        ExUnit.CaptureLog.capture_log(fn ->
          assert WardenEcto.preload_ids(plain, Warden.Test.Ecto.Issues, :read) == plain
        end)

      refute again =~ "preload_ids"
    end

    test "takes the policy or its schema, and refuses a policy the authorizer does not list" do
      _world = world()

      assert_raise Warden.PolicyError, ~r/lists no policy/, fn ->
        WardenEcto.preload_ids(actor(sam()), TeamMembership, :read)
      end

      assert_raise Warden.PolicyError, ~r/has no action :write/, fn ->
        WardenEcto.preload_ids(actor(sam()), Team, :write)
      end
    end
  end

  describe "values of another type" do
    test "within: bounds of another type are cast like the query casts them" do
      world = world()
      as_strings = webhook(tenant: "t1", bounds: %{team_ids: ["#{world.t1_private.id}", "nope"]})

      assert assert_agrees(Team, as_strings, :read) == [world.t1_private.id]
    end

    test "actor_in: a subject id that does not cast to the field's type matches nothing" do
      world = world()

      authored =
        insert!(%Issue{workspace_id: "t1", author_id: "42", team_id: world.t1_private.id})

      numeric = %{id: 42, memberships: %{"t1" => [:guest]}}
      key = %Credential{method: :api_key, scopes: ["issues:write"]}

      # An integer does not cast to the string column, in memory or in the query.
      ids = assert_agrees(Issue, actor(numeric, %{credential: key}), :write, [:team])
      refute authored.id in ids
    end
  end

  describe "guards" do
    test "update_all/4 refuses to change the tenant field or a through foreign key" do
      world = world()
      query = WardenEcto.scope(Issue, actor(sam()), :write)

      for updates <- [
            [set: [workspace_id: "t2"]],
            [set: [team_id: world.t2_public.id]],
            [inc: [team_id: 1]]
          ] do
        assert_raise Warden.PolicyError, ~r/refuses to update/, fn ->
          WardenEcto.update_all(Repo, query, updates, [])
        end
      end

      with_update = update(query, set: [team_id: ^world.t2_public.id])

      assert_raise Warden.PolicyError, ~r/refuses to update :team_id/, fn ->
        WardenEcto.update_all(Repo, with_update, [], [])
      end

      assert Repo.get!(Issue, world.i1_public.id).team_id == world.t1_public.id
      assert {_count, nil} = WardenEcto.update_all(Repo, query, [set: [title: "edited"]], [])
    end

    test "scope/4 refuses a CTE named like a table its scope reads, and allows others" do
      _world = world()
      forged = from(team in Team, select: %{id: team.id})
      shadowing = Issue |> from() |> with_cte("teams", as: ^forged)
      unrelated = Issue |> from() |> with_cte("recent", as: ^forged)

      assert_raise Warden.PolicyError,
                   ~r/CTEs named like tables its Warden scope reads \(teams\)/,
                   fn ->
                     WardenEcto.scope(shadowing, actor(sam()), :read)
                   end

      assert %Ecto.Query{} = WardenEcto.scope(unrelated, actor(sam()), :read)
    end

    test "a CTE in an outer query cannot shadow a table a nested scope reads" do
      world = world()
      forged = from(team in Team, select: %{id: team.id, team_id: team.id, user_id: "sam"})
      issues = WardenEcto.scope(Issue, actor(sam()), :read)

      outer =
        from(note in Note, join: issue in subquery(issues), on: issue.id == note.id)
        |> with_cte("team_memberships", as: ^forged)

      assert_raise Warden.PolicyError,
                   ~r/CTEs named like tables its Warden scope reads \(team_memberships\)/,
                   fn ->
                     WardenEcto.scope(outer, actor(sam()), :read)
                   end

      notes = WardenEcto.scope(Note, actor(abby()), :read)

      write =
        Issue
        |> WardenEcto.scope(actor(sam()), :write)
        |> join(:inner, [issue: issue], note in subquery(notes), on: note.id == issue.id)
        |> with_cte("notes", as: ^from(note in Note, select: %{id: note.id}))

      assert_raise Warden.PolicyError, ~r/\(notes\)/, fn ->
        WardenEcto.update_all(Repo, write, [set: [title: "edited"]], [])
      end

      assert Repo.get!(Issue, world.i1_public.id).title == "t1 public"
    end

    test "scope/4 refuses preloads and combinations, and a scoped preload works" do
      world = world()
      comment = insert!(%Comment{workspace_id: "t1", issue_id: world.i1_public.id})
      _hidden = insert!(%Comment{workspace_id: "t2", issue_id: world.i1_public.id})

      assert_raise ArgumentError, ~r/preload a scoped query/, fn ->
        Issue |> preload(:comments) |> WardenEcto.scope(actor(sam()), :read)
      end

      assert_raise ArgumentError, ~r/scope each arm/, fn ->
        Issue |> from() |> union(^from(issue in Issue)) |> WardenEcto.scope(actor(sam()), :read)
      end

      comments = WardenEcto.scope(Comment, actor(sam()), :read)

      issues_query =
        Issue
        |> WardenEcto.scope(actor(sam()), :read)
        |> where([issue: issue], issue.id == ^world.i1_public.id)

      [issue] = issues_query |> preload(comments: ^comments) |> Repo.all()
      assert ids(issue.comments) == [comment.id]
    end
  end

  describe "to_sql/4 and SQL injection" do
    test "returns the scoped SQL with parameters" do
      _world = world()
      {sql, params} = WardenEcto.to_sql(Issue, actor(sam()), :read, tenant: "t1")

      assert sql =~ ~s(FROM "issues" AS i0)
      assert sql =~ "$1"
      assert "t1" in params
    end

    test "param_offset: numbers the placeholders after the outer query's own" do
      world = world()
      query = from(issue in Issue, select: issue.id)
      {sql, params} = WardenEcto.to_sql(query, actor(sam()), :read, tenant: "t1", param_offset: 1)

      refute sql =~ "$1)"
      assert sql =~ "$2"

      raw = "SELECT count(*) FROM (#{sql}) AS scoped WHERE $1::text = 't1'"
      %{rows: [[count]]} = Repo.query!(raw, ["t1" | params])

      expected = Issue |> WardenEcto.scope(actor(sam()), :read, tenant: "t1") |> all_ids()
      assert count == length(expected)
      assert count > 0
      _unused = world

      assert_raise ArgumentError, ~r/`param_offset:` must be a non-negative integer/, fn ->
        WardenEcto.to_sql(Issue, actor(sam()), :read, param_offset: -1)
      end
    end

    test "bind: reuses the host's placeholders for the tenant and the user id" do
      world = world()
      shared = insert!(%Issue{workspace_id: "t1", team_id: world.t1_private.id, title: "shared"})
      insert!(%Share{issue_id: shared.id, grantee_id: "sam"})
      own = insert!(%Issue{workspace_id: "t1", team_id: world.t1_public.id, author_id: "sam"})
      query = from(issue in Issue, select: issue.id)
      opts = [tenant: "t1", param_offset: 2]

      {unbound_sql, unbound_params} = WardenEcto.to_sql(query, actor(sam()), :read, opts)
      bound = %{1 => "t1", 2 => "sam"}
      {sql, params} = WardenEcto.to_sql(query, actor(sam()), :read, [bind: bound] ++ opts)

      assert "t1" in unbound_params and "sam" in unbound_params
      refute "t1" in params or "sam" in params
      assert length(params) < length(unbound_params)
      assert unbound_sql =~ "$3"

      numbers =
        ~r/\$(\d+)/ |> Regex.scan(sql, capture: :all_but_first) |> List.flatten() |> Enum.uniq()

      assert numbers |> Enum.map(&String.to_integer/1) |> Enum.sort() ==
               Enum.to_list(1..(length(params) + 2))

      # The host compares its own $1 and $2 too, so both are typed by both statements.
      host = fn sql ->
        """
        SELECT issues.id FROM issues JOIN (#{sql}) AS scoped ON scoped.id = issues.id
        WHERE issues.workspace_id = $1 AND issues.author_id IS DISTINCT FROM $2
        ORDER BY issues.id
        """
      end

      %{rows: rows} = Repo.query!(host.(sql), ["t1", "sam" | params])
      %{rows: unbound_rows} = Repo.query!(host.(unbound_sql), ["t1", "sam" | unbound_params])

      expected =
        Issue
        |> WardenEcto.scope(actor(sam()), :read, tenant: "t1")
        |> all_ids()
        |> List.delete(own.id)

      assert List.flatten(rows) == expected
      assert List.flatten(unbound_rows) == expected
      assert shared.id in expected

      # A host statement with a third value of its own: the scope's values follow it.
      {offset_sql, offset_params} =
        WardenEcto.to_sql(query, actor(sam()), :read,
          tenant: "t1",
          param_offset: 3,
          bind: %{2 => "t1", 3 => "sam"}
        )

      assert offset_params == params

      raw = """
      SELECT count(*) FROM (#{offset_sql}) AS scoped
      WHERE $1::int > 0 AND $2::text = 't1' AND $3::text = 'sam'
      """

      %{rows: [[count]]} = Repo.query!(raw, [1, "t1", "sam" | offset_params])
      assert count == length(expected) + 1
    end

    test "bind: takes placeholder numbers of the host statement only" do
      _world = world()

      for {bound, offset} <- [{%{1 => "t1"}, 0}, {%{3 => "t1"}, 2}, {%{"1" => "t1"}, 1}] do
        message = ~r/`bind:` keys must be placeholder numbers from 1 to `param_offset:`/

        error =
          assert_raise ArgumentError, message, fn ->
            WardenEcto.to_sql(Issue, actor(sam()), :read, bind: bound, param_offset: offset)
          end

        refute error.message =~ "t1"
      end

      assert_raise ArgumentError,
                   ~r/`bind:` must be a map of placeholder numbers to values, got: a list/,
                   fn ->
                     WardenEcto.to_sql(Issue, actor(sam()), :read,
                       bind: [{1, "t1"}],
                       param_offset: 1
                     )
                   end
    end

    test "tenant ids and where: literals stay parameters" do
      world = world()
      hostile = "t1'; DROP TABLE teams; --"
      user = %{id: "abby' OR '1'='1", memberships: %{hostile => [:owner]}}

      team =
        insert!(%Team{
          workspace_id: hostile,
          name: "o'brien\"; DROP TABLE teams; --",
          private: true
        })

      {sql, params} = WardenEcto.to_sql(Team, actor(user), :read, [])
      refute sql =~ "DROP TABLE"
      refute sql =~ "o'brien"
      assert hostile in params
      assert "o'brien\"; DROP TABLE teams; --" in params

      assert scope_ids(Team, actor(user), :read) == [team.id]
      assert scope_ids(Issue, actor(user), :read) == []
      assert Repo.get!(Team, world.t1_public.id)
    end
  end

  describe "telemetry" do
    test "scopes and checks emit decisions with layer :ecto, without subjects or values" do
      world = world()
      Decisions.attach()

      _query = WardenEcto.scope(Issue, actor(sam()), :read, tenant: "t1")

      assert_received {:decision, %{count: 1, denied: 0},
                       %{layer: :ecto, kind: :scope, tenant: "t1"} = scope}

      assert scope.rule == {:can, Warden.Test.Ecto.Issues, :read, []}

      refute WardenEcto.allowed?(actor(sam()), :read, world.i2_public)
      assert_received {:decision, %{count: 1, denied: 1}, %{layer: :ecto, kind: :call} = call}

      _filtered = WardenEcto.filter(actor(sam()), :read, [world.i1_public, world.i2_public])
      assert_received {:decision, %{count: 2, denied: 1}, %{layer: :ecto}}

      for metadata <- [scope, call], value <- Map.values(metadata) do
        refute inspect(value) =~ "sam"
      end
    end
  end

  describe "Dataloader" do
    test "dataloader_query/2 scopes loads of schemas with a policy" do
      world = world()

      source =
        Dataloader.Ecto.new(Repo,
          query: &WardenEcto.dataloader_query/2,
          default_params: %{warden_actor: actor(sam())}
        )

      loader =
        Dataloader.new()
        |> Dataloader.add_source(:db, source)
        |> Dataloader.load_many(:db, Issue, [world.i1_public.id, world.i2_public.id])
        |> Dataloader.load_many(:db, TeamMembership, [1])
        |> Dataloader.run()

      [visible, hidden] =
        Dataloader.get_many(loader, :db, Issue, [world.i1_public.id, world.i2_public.id])

      assert visible.id == world.i1_public.id
      assert hidden == nil

      comment = insert!(%Comment{workspace_id: "t2", issue_id: world.i2_public.id})
      loader = loader |> Dataloader.load(:db, :issue, comment) |> Dataloader.run()
      assert Dataloader.get(loader, :db, :issue, comment) == nil
    end
  end
end
