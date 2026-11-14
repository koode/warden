defmodule Warden.RedteamV2Ecto.ScopeHolesTest do
  # Red-team of Warden.Ecto against Postgres. Every test asserts the secure behaviour, so a
  # failing test is an open hole; each one names the security goal it attacks.
  use Warden.Test.EctoCase, async: true

  alias Warden.Credential
  alias Warden.Ecto, as: WardenEcto
  alias Warden.RedteamV2Ecto.Authz, as: RedteamAuthz
  alias Warden.RedteamV2Ecto.People, as: RedteamPeople
  alias Warden.Test.Ecto.{Comment, Issue, Team, TeamMembership}

  defp scope_ids(queryable, actor_or_context, action, opts \\ []) do
    queryable |> WardenEcto.scope(actor_or_context, action, opts) |> all_ids()
  end

  # `{:ok, ids}` of the scoped query, or `:refused` when Warden refuses to scope it.
  defp scoped_or_refused(fun) do
    {:ok, fun.()}
  rescue
    _error in [ArgumentError, Warden.PolicyError] -> :refused
  end

  defp expiry_outcome(fun) do
    {:ok, fun.()}
  rescue
    error in DBConnection.EncodeError -> {:raised, error}
  end

  defp write_or_refused(fun) do
    {:ok, fun.()}
  rescue
    _error in [ArgumentError, Warden.PolicyError] -> :refused
  end

  describe "HOLE goal 10: delegation bounds replace the acting actor's own bounds" do
    test "on_behalf_of/3 bounds never widen the credential bounds of the acting actor" do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      first = insert!(%Issue{workspace_id: "t1", team_id: team.id, title: "first"})
      second = insert!(%Issue{workspace_id: "t1", team_id: team.id, title: "second"})

      # An agent key limited to the first issue, delegated by Abby, who may read both.
      credential = %Credential{method: :api_key, bounds: %{issue_ids: [first.id]}}
      agent = actor(olivia(), %{credential: credential})
      user = actor(abby())
      delegation_bounds = %{issue_ids: [first.id, second.id]}
      effective = Warden.on_behalf_of(agent, user, bounds: delegation_bounds)

      agent_ids = scope_ids(Issue, agent, :read)
      user_ids = scope_ids(Issue, user, :read)
      assert first.id in agent_ids
      refute second.id in agent_ids
      assert second.id in user_ids

      effective_ids = scope_ids(Issue, effective, :read)
      refute second.id in effective_ids, "the delegated actor is wider than the agent alone"
      refute WardenEcto.allowed?(effective, :read, second)
      refute WardenEcto.allowed?(effective, :read, {Issue, second.id})
    end
  end

  describe "HOLE goal 8: scope/4 of a query with combinations" do
    test "a union arm after the first is left unscoped" do
      _public = insert!(%Team{workspace_id: "t1", name: "t1 public"})
      _secret = insert!(%Team{workspace_id: "t2", name: "t2 private", private: true})
      t1_query = from(team in Team, where: team.workspace_id == "t1")
      t2_query = from(team in Team, where: team.workspace_id == "t2")
      combined = union_all(t1_query, ^t2_query)
      allowed = scope_ids(Team, actor(sam()), :read)

      outcome = scoped_or_refused(fn -> scope_ids(combined, actor(sam()), :read) end)

      case outcome do
        :refused -> :ok
        {:ok, ids} -> assert ids -- allowed == [], "rows outside the scope: #{inspect(ids)}"
      end
    end
  end

  describe "HOLE goal 8: in-memory through_any: trusts children of another parent" do
    test "a loaded comment whose issue_id points elsewhere does not admit this issue" do
      issue = insert!(%Issue{workspace_id: "t1", title: "not Sam's"})
      other_issue = insert!(%Issue{workspace_id: "t1", title: "Sam commented here"})
      comment = insert!(%Comment{workspace_id: "t1", issue_id: other_issue.id, author_id: "sam"})
      sam = RedteamPeople.actor(RedteamPeople.sam())

      refute issue.id in scope_ids(Issue, sam, :read)
      assert other_issue.id in scope_ids(Issue, sam, :read)

      # The struct's preload names a comment that belongs to another issue.
      mismatched = %{issue | comments: [comment]}
      refute WardenEcto.allowed?(sam, :read, mismatched)
      assert WardenEcto.filter(sam, :read, [mismatched]) == []
    end
  end

  describe "HOLE goal 8: in-memory within: with a nil in the bounds" do
    test "a NULL column is never inside the bounds, in memory or in SQL" do
      team = insert!(%Team{workspace_id: "t1", name: "bounded"})
      teamless = insert!(%Issue{workspace_id: "t1", title: "no team"})
      on_team = insert!(%Issue{workspace_id: "t1", team_id: team.id})
      credential = %Credential{method: :api_key, bounds: %{team_ids: [nil, team.id]}}
      agent = RedteamPeople.actor(RedteamPeople.olivia(), %{credential: credential})

      scoped = scope_ids(Issue, agent, :read)
      assert on_team.id in scoped
      refute teamless.id in scoped

      assert WardenEcto.allowed?(agent, :read, teamless) == teamless.id in scoped
    end
  end

  describe "HOLE goal 8: query prefixes" do
    setup do
      statements = [
        "CREATE SCHEMA rt_prefix_b",
        "CREATE TABLE rt_prefix_b.teams (LIKE public.teams INCLUDING ALL)",
        "CREATE TABLE rt_prefix_b.team_memberships (LIKE public.team_memberships INCLUDING ALL)",
        "CREATE TABLE rt_prefix_b.issues (LIKE public.issues INCLUDING ALL)"
      ]

      Enum.each(statements, &Repo.query!/1)

      # The same team id in both prefixes: Sam is a member of the public one only.
      team = %Team{id: 990_001, workspace_id: "t1", name: "private", private: true}
      insert!(team)
      Repo.insert!(team, prefix: "rt_prefix_b")
      insert!(%TeamMembership{team_id: 990_001, user_id: "sam"})
      guest = %{id: "sam", memberships: %{"t1" => [:guest]}}
      %{guest: guest}
    end

    test "a struct loaded from another prefix is decided against its own prefix", %{guest: guest} do
      loaded = Repo.get!(Team, 990_001, prefix: "rt_prefix_b")
      assert loaded.__meta__.prefix == "rt_prefix_b"

      refute WardenEcto.allowed?(actor(guest), :read, loaded)
      assert WardenEcto.filter(actor(guest), :read, [loaded]) == []
    end

    test "resolve: :ids reads the parent ids of the struct's own prefix", %{guest: guest} do
      issue = %Issue{id: 990_002, workspace_id: "t1", team_id: 990_001, title: "T"}
      insert!(issue)
      Repo.insert!(issue, prefix: "rt_prefix_b")
      public = Repo.get!(Issue, 990_002)
      other = Repo.get!(Issue, 990_002, prefix: "rt_prefix_b")

      assert WardenEcto.allowed?(actor(guest), :read_ids, public)
      refute WardenEcto.allowed?(actor(guest), :read_ids, other)
      assert WardenEcto.filter(actor(guest), :read_ids, [public, other]) == [public]
    end

    test "scope/4 run with a prefix checks the link rows of that prefix", %{guest: guest} do
      query = WardenEcto.scope(Team, actor(guest), :read)
      prefixed = Repo.all(query, prefix: "rt_prefix_b")
      assert Enum.map(prefixed, & &1.id) == []
    end
  end

  describe "HOLE goals 8, 11: update_all/4 checks the rows before the write only" do
    test "a credential bound to t1 cannot move its rows into t2" do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      issue = insert!(%Issue{workspace_id: "t1", team_id: team.id})
      key = context(sam(), %{credential: %Credential{method: :session, tenant: "t1"}})
      query = WardenEcto.scope(Issue, key, :write, authorizer: Warden.Test.Ecto.Authz)
      updates = [set: [workspace_id: "t2"]]

      _outcome = write_or_refused(fn -> WardenEcto.update_all(Repo, query, updates, []) end)

      assert Repo.get!(Issue, issue.id).workspace_id == "t1",
             "a write scope moved a row into a tenant the credential is not bound to"
    end
  end

  describe "HOLE goal 8: a CTE named like a policy table" do
    test "update_all/4 refuses a write scope whose link table a CTE shadows" do
      private = insert!(%Team{workspace_id: "t1", name: "private", private: true})
      issue = insert!(%Issue{workspace_id: "t1", team_id: private.id, title: "untouched"})
      guest = actor(%{id: "sam", memberships: %{"t1" => [:member]}})
      refute issue.id in scope_ids(Issue, guest, :write)

      forged_query =
        from(team in Team,
          select: %{id: team.id, team_id: team.id, user_id: type(^"sam", :string)}
        )

      query =
        Issue
        |> WardenEcto.scope(guest, :write)
        |> with_cte("team_memberships", as: ^forged_query)

      updates = [set: [title: "edited"]]
      _outcome = write_or_refused(fn -> WardenEcto.update_all(Repo, query, updates, []) end)

      assert Repo.get!(Issue, issue.id).title == "untouched"
    end
  end

  describe "HOLE goal 8: preloads of a scoped query" do
    test "a preload in a scoped query is scoped by the child's policy, or refused" do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      issue = insert!(%Issue{workspace_id: "t1", team_id: team.id})
      hidden = insert!(%Comment{workspace_id: "t2", issue_id: issue.id, body: "t2 only"})
      query = from(issue in Issue, preload: :comments)

      outcome =
        scoped_or_refused(fn ->
          query |> WardenEcto.scope(actor(sam()), :read) |> Repo.all()
        end)

      refute hidden.id in scope_ids(Comment, actor(sam()), :read)

      case outcome do
        :refused ->
          :ok

        {:ok, issues} ->
          loaded = for issue <- issues, comment <- issue.comments, do: comment.id
          refute hidden.id in loaded
      end
    end
  end

  describe "grant: expiry through a table name with timestamptz" do
    setup do
      table = """
      CREATE TABLE rt_team_grants (
        id bigserial PRIMARY KEY,
        team_id bigint NOT NULL,
        grantee_id text NOT NULL,
        expires_at timestamptz
      )
      """

      Repo.query!(table)
      :ok
    end

    test "a grant that expired two hours ago denies, whatever the session time zone" do
      team = insert!(%Team{workspace_id: "t1", name: "shared"})

      grant = """
      INSERT INTO rt_team_grants (team_id, grantee_id, expires_at)
      VALUES ($1, 'sam', now() - interval '2 hours')
      """

      Repo.query!(grant, [team.id])
      sam = RedteamPeople.actor(RedteamPeople.sam())

      for zone <- ["UTC", "Pacific/Kiritimati", "America/Los_Angeles"] do
        Repo.query!("SET LOCAL TIME ZONE '#{zone}'")
        outcome = expiry_outcome(fn -> scope_ids(Team, sam, :read) end)
        refute outcome == {:ok, [team.id]}, "an expired grant admits the team in #{zone}"
      end
    end

    # Fails closed today, but not usable: the naive "now" cannot be encoded as a
    # timestamptz parameter, so every query of the policy raises.
    test "LOW: an unexpired grant through a table name with timestamptz admits the team" do
      team = insert!(%Team{workspace_id: "t1", name: "shared"})

      grant = """
      INSERT INTO rt_team_grants (team_id, grantee_id, expires_at)
      VALUES ($1, 'sam', now() + interval '2 hours')
      """

      Repo.query!(grant, [team.id])
      sam = RedteamPeople.actor(RedteamPeople.sam())
      outcome = expiry_outcome(fn -> scope_ids(Team, sam, :read) end)
      assert outcome == {:ok, [team.id]}
    end
  end

  describe "HOLE: dataloader_query/2 with a subquery root" do
    test "a load whose root is a subquery over a policy schema is not passed through" do
      _secret = insert!(%Team{workspace_id: "t2", name: "t2 private", private: true})
      inner_query = from(team in Team)
      queryable = subquery(inner_query)
      params = %{warden_actor: actor(sam())}

      outcome =
        scoped_or_refused(fn ->
          query = WardenEcto.dataloader_query(queryable, params)
          rows_query = from(row in query, select: row.id)
          Repo.all(rows_query)
        end)

      case outcome do
        :refused -> :ok
        {:ok, ids} -> assert ids == []
      end
    end
  end

  describe "held: guarded writes refuse unscoped and widened queries" do
    setup do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      mine = insert!(%Issue{workspace_id: "t1", team_id: team.id, title: "mine"})
      theirs = insert!(%Issue{workspace_id: "t2", title: "theirs"})
      %{mine: mine, theirs: theirs}
    end

    test "a read scope, or_where, exclude(:where), unions, joins and subqueries", context do
      sam = actor(sam())
      write = WardenEcto.scope(Issue, sam, :write)
      read = WardenEcto.scope(Issue, sam, :read)
      widened = or_where(write, [issue: issue], issue.id == ^context.theirs.id)
      excluded = exclude(write, :where)
      plain_query = from(issue in Issue)
      unioned = union_all(write, ^plain_query)
      joined = from(issue in Issue, join: scoped in subquery(write), on: scoped.id == issue.id)
      wrapped = from(row in subquery(write))
      both_query = WardenEcto.scope(Issue, sam, :read)
      rescoped = both_query |> WardenEcto.scope(sam, :write) |> or_where([issue: issue], true)
      updates = [set: [title: "x"]]

      for query <- [read, widened, excluded, unioned, joined, wrapped, rescoped] do
        outcome = write_or_refused(fn -> WardenEcto.update_all(Repo, query, updates, []) end)
        assert outcome == :refused
      end

      assert_raise ArgumentError, fn ->
        query = from(row in subquery(write))
        WardenEcto.scope(query, sam, :write)
      end

      assert Repo.get!(Issue, context.theirs.id).title == "theirs"
    end

    test "a later and-where narrows and is accepted", context do
      query =
        Issue
        |> WardenEcto.scope(actor(sam()), :write)
        |> where([issue: issue], issue.id == ^context.mine.id)

      assert {1, nil} = WardenEcto.update_all(Repo, query, [set: [title: "edited"]], [])
      assert Repo.get!(Issue, context.theirs.id).title == "theirs"
    end

    test "or_where before the scope stays inside it", context do
      query =
        from(issue in Issue,
          where: issue.id == ^context.mine.id,
          or_where: issue.id == ^context.theirs.id
        )

      scoped = WardenEcto.scope(query, actor(sam()), :write)
      assert {1, nil} = WardenEcto.update_all(Repo, scoped, [set: [title: "edited"]], [])
      assert Repo.get!(Issue, context.theirs.id).title == "theirs"
    end
  end

  describe "held: query composition" do
    test "a join named like the policy binding, and a root named otherwise, are refused" do
      clashing = from(issue in Issue, join: comment in Comment, as: :issue, on: true)
      renamed = from(issue in Issue, as: :other)

      assert_raise ArgumentError, fn -> WardenEcto.scope(clashing, actor(sam()), :read) end
      assert_raise ArgumentError, fn -> WardenEcto.scope(renamed, actor(sam()), :read) end
    end

    test "a join named like a through parent's binding does not capture the parent" do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      allowed = insert!(%Issue{workspace_id: "t1", team_id: team.id})
      hidden = insert!(%Issue{workspace_id: "t2", title: "hidden"})
      _on_allowed = insert!(%Comment{workspace_id: "t1", issue_id: allowed.id})
      _on_hidden = insert!(%Comment{workspace_id: "t2", issue_id: hidden.id})

      # The user's join is named :issue, the binding of the Issues policy that the
      # Comments policy reaches through.
      query =
        from(comment in Comment,
          join: issue in Issue,
          as: :issue,
          on: issue.id == ^allowed.id,
          select: comment.issue_id
        )

      issue_ids = query |> WardenEcto.scope(actor(sam()), :read) |> Repo.all()
      assert issue_ids == [allowed.id]
    end

    test "joins, distinct, limit and a select without the id keep the scope" do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      allowed = insert!(%Issue{workspace_id: "t1", team_id: team.id, title: "allowed"})
      _hidden = insert!(%Issue{workspace_id: "t2", title: "hidden"})

      query =
        from(issue in Issue,
          left_join: comment in assoc(issue, :comments),
          distinct: true,
          limit: 10,
          select: issue.title
        )

      titles = query |> WardenEcto.scope(actor(sam()), :read) |> Repo.all()
      assert titles == [allowed.title]
    end
  end

  describe "held: ids and tenants" do
    test "string, hostile, unknown and foreign-schema ids deny or match by cast" do
      team = insert!(%Team{workspace_id: "t1", name: "public"})
      issue = insert!(%Issue{workspace_id: "t1", team_id: team.id})
      sam = actor(sam())

      assert WardenEcto.allowed?(sam, :read, {Issue, Integer.to_string(issue.id)})
      refute WardenEcto.allowed?(sam, :read, {Issue, "#{issue.id} OR 1=1"})
      refute WardenEcto.allowed?(sam, :read, {Issue, nil})
      refute WardenEcto.allowed?(sam, :read, {Issue, -1})
      refute WardenEcto.allowed?(sam, :read, {Issue, [issue.id]})
      refute Warden.allowed?(sam, Warden.Rule.can(Warden.Test.Ecto.Issues, :read), value: team)

      duplicated = WardenEcto.filter(sam, :read, [{Issue, issue.id}, {Issue, issue.id}])
      assert duplicated == [{Issue, issue.id}, {Issue, issue.id}]
    end

    test "tenants/2 returning duplicates and nil adds no NULL-tenant rows" do
      orphan = insert!(%Issue{workspace_id: nil, title: "orphan"})
      context = RedteamPeople.context(RedteamPeople.sam(), %{tenants_result: ["t1", "t1", nil]})
      ids = scope_ids(Issue, context, :read, authorizer: RedteamAuthz)
      refute orphan.id in ids
      refute WardenEcto.allowed?(context, :read, orphan, authorizer: RedteamAuthz)
    end

    test "tenants/2 returning something other than a list raises" do
      context = RedteamPeople.context(RedteamPeople.sam(), %{tenants_result: {:ok, ["t1"]}})

      assert_raise Warden.PolicyError, fn ->
        WardenEcto.scope(Issue, context, :read, authorizer: RedteamAuthz)
      end
    end

    test "an explicit tenant the bound credential is not bound to gives nothing" do
      _team = insert!(%Team{workspace_id: "t2", name: "t2 public"})
      key = context(abby(), %{credential: %Credential{method: :api_key, tenant: "t1"}})
      ids = scope_ids(Team, key, :read, authorizer: Warden.Test.Ecto.Authz, tenant: "t2")
      assert ids == []
    end

    test "a hostile tenant in to_sql/4 stays a parameter" do
      hostile = "t1') OR 1=1 --"
      user = %{id: "x' OR '1'='1", memberships: %{hostile => [:member]}}
      {sql, params} = WardenEcto.to_sql(Issue, actor(user), :read, tenant: hostile)
      refute sql =~ "OR 1=1"
      assert hostile in params
    end
  end

  describe "held: allowed_actors/3 does not leak between actors" do
    test "each actor gets its own answer in the one query" do
      private = insert!(%Team{workspace_id: "t1", name: "private", private: true})
      insert!(%TeamMembership{team_id: private.id, user_id: "sam"})
      issue = insert!(%Issue{workspace_id: "t1", team_id: private.id})
      sam = actor(sam())
      abby = actor(abby())
      kim = actor(kim())
      delegated = Warden.on_behalf_of(actor(olivia()), abby, bounds: %{issue_ids: [issue.id]})

      for row <- [issue, {Issue, issue.id}] do
        audience = WardenEcto.allowed_actors([kim, sam, abby, delegated], :read, row)
        assert audience == [sam], inspect(row)
      end
    end
  end

  describe "held: through_type: and stale through: preloads" do
    test "a type name in another case denies in memory and in SQL" do
      project = insert!(%Warden.Test.Ecto.Project{workspace_id: "t1"})
      cased = %Warden.Test.Ecto.Summary{workspace_id: "t1", subject_type: "Project"}
      summary = insert!(%{cased | subject_id: project.id})
      sam = actor(sam())

      refute summary.id in scope_ids(Warden.Test.Ecto.Summary, sam, :read)
      refute WardenEcto.allowed?(sam, :read, summary)
    end

    test "a preloaded parent that no longer matches the foreign key goes to the database" do
      public = insert!(%Team{workspace_id: "t1", name: "public"})
      private = insert!(%Team{workspace_id: "t1", name: "private", private: true})
      issue = insert!(%Issue{workspace_id: "t1", team_id: private.id})
      guest = actor(%{id: "sam", memberships: %{"t1" => [:member]}})

      stale = %{issue | team: public}
      refute WardenEcto.allowed?(guest, :read, stale)
    end
  end
end
