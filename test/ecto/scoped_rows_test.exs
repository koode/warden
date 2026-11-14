defmodule Warden.Ecto.ScopedRowsTest do
  # Rows loaded through `Warden.Ecto.all/5` are trusted by the policy that scoped them,
  # for the same actor instance and action only.
  use Warden.Test.EctoCase, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Ecto.{Authz, Comments, Issue, Issues, Note, Notes, Team}

  @both_tenants %{id: "lee", memberships: %{"t1" => [:member], "t2" => [:member]}}

  setup do
    t1 = insert!(%Team{workspace_id: "t1"})
    t2 = insert!(%Team{workspace_id: "t2"})

    issues =
      for team <- [t1, t1, t2, t2] do
        insert!(%Issue{workspace_id: team.workspace_id, team_id: team.id, author_id: "abby"})
      end

    %{issues: issues}
  end

  defp read_rule, do: Warden.Rule.can(Issues, :read)

  defp load(actor, opts \\ []) do
    query = from(issue in Issue, order_by: issue.id)
    WardenEcto.all(Repo, query, actor, :read, opts)
  end

  describe "Warden.Ecto.all/5" do
    test "returns the rows of the scope" do
      for user <- [abby(), sam(), kim(), @both_tenants] do
        actor = actor(user)
        scoped = Issue |> WardenEcto.scope(actor, :read) |> all_ids()
        assert actor |> load() |> ids() |> Enum.sort() == scoped
      end
    end

    test "takes the scope options and passes the rest to the repo" do
      actor = actor(@both_tenants)
      rows = load(actor, tenant: "t2", authorizer: Authz)
      assert Enum.map(rows, & &1.workspace_id) == ["t2", "t2"]
    end

    test "never marks a struct selected from another binding" do
      actor = actor(@both_tenants)

      query =
        from(issue in Issue,
          join: other in Issue,
          on: other.workspace_id == issue.workspace_id,
          select: other
        )

      rows = WardenEcto.all(Repo, query, actor, :read)
      assert rows != []
      assert Enum.all?(rows, &(&1.__meta__.context == nil))

      {_allowed, count} = count_queries(fn -> WardenEcto.filter(actor, :read, rows) end)
      assert count > 0
    end

    test "marks a partial select of the root, never a select_merge" do
      actor = actor(@both_tenants)
      partial = from(issue in Issue, select: [:id, :workspace_id])
      rows = WardenEcto.all(Repo, partial, actor, :read)
      assert [_first, _second, _third, _fourth] = rows

      {filtered, count} = count_queries(fn -> WardenEcto.filter(actor, :read, rows) end)
      assert filtered == rows
      assert count == 0

      merged = from(issue in Issue, select_merge: %{title: "changed"})
      rows = WardenEcto.all(Repo, merged, actor, :read)
      assert Enum.all?(rows, &(&1.__meta__.context == nil))
    end

    test "keeps rows that are not structs of the schema as they are" do
      actor = actor(@both_tenants)
      query = from(issue in Issue, select: issue.id)
      loaded = WardenEcto.all(Repo, query, actor, :read)
      assert Enum.sort(loaded) == all_ids(Issue)
    end
  end

  describe "rows loaded with all/5" do
    test "are decided without a policy query, by every entry point" do
      actor = actor(@both_tenants)
      rows = load(actor)
      assert [_first, _second, _third, _fourth] = rows

      {filtered, count} = count_queries(fn -> Warden.filter(actor, read_rule(), rows) end)
      assert filtered == rows
      assert count == 0

      {filtered, count} = count_queries(fn -> WardenEcto.filter(actor, :read, rows) end)
      assert filtered == rows
      assert count == 0

      {answers, count} =
        count_queries(fn -> Enum.map(rows, &WardenEcto.allowed?(actor, :read, &1)) end)

      assert Enum.all?(answers)
      assert count == 0
    end

    test "in a GraphQL list under a can/2 object rule need only the resolver's query" do
      context = context(@both_tenants)

      {{:ok, %{data: %{"scopedIssues" => scoped}}}, count} =
        count_queries(fn ->
          Absinthe.run("{ scopedIssues { id } }", Warden.Test.Ecto.GraphQL, context: context)
        end)

      assert [_first, _second, _third, _fourth] = scoped
      assert count == 1

      # The same list loaded without marks costs one query per tenant on top.
      {{:ok, %{data: %{"issues" => issues}}}, count} =
        count_queries(fn ->
          Absinthe.run("{ issues { id } }", Warden.Test.Ecto.GraphQL, context: context)
        end)

      assert issues == scoped
      assert count == 3
    end

    test "in a GraphQL list resolved in a later Dataloader pass need only the resolver's query" do
      context = context(@both_tenants)

      {{:ok, %{data: %{"scopedIssuesAfterLoad" => scoped}}}, count} =
        count_queries(fn ->
          Absinthe.run("{ scopedIssuesAfterLoad { id } }", Warden.Test.Ecto.GraphQL,
            context: context
          )
        end)

      assert [_first, _second, _third, _fourth] = scoped
      assert count == 1
    end

    test "agree with the scope in Warden.Test.assert_policy_consistent/4" do
      actor = actor(@both_tenants)
      other = actor(sam())
      rows = load(actor)

      cells = Warden.Test.assert_policy_consistent(Issues, [lee: actor, sam: other], rows)
      assert cells[{:lee, "row 1", :read}]
      assert cells[{:sam, "row 1", :read}]
      refute cells[{:sam, "row 3", :read}]

      # The marked rows get the answers the policy gives the unmarked ones.
      for {row, index} <- Enum.with_index(rows, 1), {name, side} <- [lee: actor, sam: other] do
        assert WardenEcto.allowed?(side, :read, row) == cells[{name, "row #{index}", :read}]
      end
    end

    test "are explained as admitted by their scope, after the gates" do
      actor = actor(@both_tenants)
      [row | _rest] = load(actor)

      explanation = WardenEcto.explain(actor, :read, row)
      assert explanation.result == :ok
      assert [%{rule: {:admitted_by_scope, :read}, result: :ok}] = explanation.steps

      rebuilt = WardenEcto.explain(actor(@both_tenants), :read, row)
      assert rebuilt.result == :ok
      refute Enum.any?(rebuilt.steps, &match?(%{rule: {:admitted_by_scope, _action}}, &1))
    end

    test "of a delegated actor are trusted for both sides of that actor" do
      agent = actor(%{id: "bot", kind: :agent, memberships: %{"t1" => [:member]}})
      delegated = Warden.on_behalf_of(agent, actor(@both_tenants))
      rows = load(delegated)
      assert Enum.map(rows, & &1.workspace_id) == ["t1", "t1"]

      {filtered, count} = count_queries(fn -> Warden.filter(delegated, read_rule(), rows) end)
      assert filtered == rows
      assert count == 0
    end
  end

  describe "a mark is ignored" do
    test "for another instance of the same user" do
      rows = load(actor(@both_tenants))
      rebuilt = actor(@both_tenants)

      {filtered, count} = count_queries(fn -> Warden.filter(rebuilt, read_rule(), rows) end)
      assert filtered == rows
      assert count == 2
    end

    test "for a context map, which builds a new actor" do
      rows = load(actor(@both_tenants))

      {_filtered, count} =
        count_queries(fn ->
          WardenEcto.filter(context(@both_tenants), :read, rows, authorizer: Authz)
        end)

      assert count == 2
    end

    test "for an actor acting on behalf of the actor that loaded the rows" do
      user = actor(@both_tenants)
      rows = load(user)
      agent = actor(%{id: "bot", kind: :agent, memberships: %{"t1" => [:member]}})
      delegated = Warden.on_behalf_of(agent, user)

      {filtered, count} = count_queries(fn -> Warden.filter(delegated, read_rule(), rows) end)
      assert Enum.map(filtered, & &1.workspace_id) == ["t1", "t1"]
      assert count > 0
    end

    test "for the agent and the delegator of the actor that loaded the rows" do
      user = actor(@both_tenants)
      agent = actor(%{id: "bot", kind: :agent, memberships: %{"t1" => [:member]}})
      rows = load(Warden.on_behalf_of(agent, user))

      for side <- [agent, user] do
        {_filtered, count} = count_queries(fn -> Warden.filter(side, read_rule(), rows) end)
        assert count > 0
      end
    end

    test "for another action" do
      read_only = %Warden.Credential{method: :api_key, scopes: ["issues:read"]}
      actor = actor(@both_tenants, %{credential: read_only})
      rows = load(actor)
      assert [_first, _second, _third, _fourth] = rows

      # A key that may read every issue but write none: the :read mark says nothing
      # about :write.
      assert WardenEcto.filter(actor, :read, rows) == rows
      assert WardenEcto.filter(actor, :write, rows) == []
    end

    test "for a context of another shape" do
      actor = actor(sam())

      forged =
        for row <- Repo.all(Issue),
            context <- [:admitted, {:warden, :admitted}, %{policy: Issues, action: :read}] do
          Ecto.put_meta(row, context: context)
        end

      {filtered, count} = count_queries(fn -> WardenEcto.filter(actor, :read, forged) end)
      assert Enum.all?(filtered, &(&1.workspace_id == "t1"))
      assert Enum.count(filtered) == 6
      assert count > 0
    end

    test "for a struct changed after loading" do
      actor = actor(sam())
      [row | _rest] = load(actor)

      # The policy reads only live issues; the in-memory decision sees the change.
      trashed = %{row | trashed_at: ~U[2026-01-01 00:00:00Z]}
      refute WardenEcto.allowed?(actor, :read, trashed)
    end

    test "for a struct whose clause field, tenant or prefix changed" do
      actor = actor(@both_tenants)
      [row | _rest] = load(actor)
      other_team = insert!(%Team{workspace_id: "t1"})

      changed = [
        %{row | team_id: other_team.id},
        %{row | workspace_id: "t2"},
        %{row | author_id: "kim"},
        Ecto.put_meta(row, prefix: "public")
      ]

      for struct <- changed do
        {_allowed, count} = count_queries(fn -> WardenEcto.filter(actor, :read, [struct]) end)
        assert count > 0
      end
    end

    test "of a policy with a hand-written scope/4, for a change to any persisted field" do
      actor = actor(abby())
      insert!(%Note{workspace_id: "t1", author_id: "abby"})
      [note] = WardenEcto.all(Repo, Note, actor, :read)

      assert WardenEcto.allowed?(actor, :read, note)
      refute_received {:allowed?, :read, _id}

      # Nothing tells which fields a hand-written scope reads, so every one counts.
      assert WardenEcto.allowed?(actor, :read, %{note | secret: true})
      assert_received {:allowed?, :read, _id}
    end

    test "for another policy" do
      actor = actor(@both_tenants)
      [row | _rest] = load(actor)
      mark = row.__meta__.context
      forged = Ecto.put_meta(row, context: %{mark | call: %{mark.call | policy: Comments}})

      {[^forged], count} = count_queries(fn -> WardenEcto.filter(actor, :read, [forged]) end)
      assert count > 0
    end

    test "when the same actor is bound to another tenant" do
      actor = actor(@both_tenants)
      [_first, _second, t2_row, _fourth] = load(actor)

      bound = %{actor | credential: %Warden.Credential{method: :api_key, tenant: "t1"}}

      assert {:error, %Warden.Denial{reason: :tenant_binding}} =
               Warden.authorize(bound, read_rule(), value: t2_row)

      refute WardenEcto.allowed?(bound, :read, t2_row)
    end
  end

  describe "a mark is kept" do
    # The mark holds only the fields a decision of the policy can read: the primary key,
    # the tenant and the fields its clauses read (Issues: team_id, trashed_at, author_id).
    # A change to any other field cannot change the scope's answer.
    test "for a struct changed in a field no clause of its policy reads" do
      actor = actor(@both_tenants)
      rows = load(actor)

      retitled =
        Enum.map(rows, &%{&1 | title: "renamed", state: :closed, priority: Decimal.new(9)})

      {filtered, count} = count_queries(fn -> WardenEcto.filter(actor, :read, retitled) end)
      assert filtered == retitled
      assert count == 0
    end

    test "for the fields a decision of the policy reads, or every field" do
      issue_fields = Issues.__warden_ecto__(:info).mark_fields
      assert issue_fields == [:id, :workspace_id, :author_id, :trashed_at, :team_id]
      assert Notes.__warden_ecto__(:info).mark_fields == :all
    end

    test "with one call-level term shared by every row of the call" do
      actor = actor(@both_tenants)
      [first, second | _rest] = load(actor)
      assert :erts_debug.same(first.__meta__.context.call, second.__meta__.context.call)
    end
  end

  test "the mark never shows in inspect output beyond the policy and action" do
    actor = actor(@both_tenants)
    [row | _rest] = load(actor)
    inspected = inspect(row)

    assert inspected =~ "Warden.Ecto.Mark"
    refute inspected =~ "lee"
    refute inspected =~ "#Reference"
  end
end
