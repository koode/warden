defmodule Warden.Ecto.MatrixFailuresTest do
  # What the matrix helpers report when something is wrong.
  use Warden.Test.EctoCase, async: true

  import Warden.Test.CompileHelpers

  alias Warden.Test.Absinthe, as: AbsintheMatrix
  alias Warden.Test.Ecto.{Authz, BrokenAuthz, BrokenNotes, Comment, Issue, Note, OauthClient}
  alias Warden.Test.Ecto.{Project, Summary, Team, TeamMembership}
  alias Warden.Test.Matrix
  alias Warden.Test.V2.{Doc, Docs, People}

  defp snapshot_path do
    dir = Path.join(System.tmp_dir!(), "warden_matrix_#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    Path.join(dir, "matrix.snapshot")
  end

  # One resource per policy of the Ecto suite's authorizer.
  defp resources do
    team = insert!(%Team{workspace_id: "t1", name: "Team Rocket"})
    issue = insert!(%Issue{workspace_id: "t1", team_id: team.id, title: "Secret title"})
    comment = insert!(%Comment{workspace_id: "t1", issue_id: issue.id, body: "Secret body"})

    [
      team: team,
      issue: issue,
      comment: comment,
      project: insert!(%Project{workspace_id: "t1", name: "Secret project"}),
      summary: insert!(%Summary{workspace_id: "t1", subject_type: "team", subject_id: team.id}),
      client: insert!(%OauthClient{workspace_id: "t1", name: "Secret client"}),
      note: insert!(%Note{workspace_id: "t1", author_id: "abby"})
    ]
  end

  defp matrix(actors, resources, snapshot) do
    %Matrix{
      authorizer: Authz,
      repo: Repo,
      snapshot: snapshot,
      actors: actors,
      resources: resources
    }
  end

  describe "consistency" do
    test "assert_policy_consistent/4 names the cell where allowed?/4 and scope/4 disagree" do
      secret = insert!(%Note{workspace_id: "t1", author_id: "abby", secret: true})
      open = insert!(%Note{workspace_id: "t1", author_id: "abby"})
      member = context(%{id: "sam", memberships: %{"t1" => [:member]}})

      error =
        assert_raise ExUnit.AssertionError, fn ->
          Warden.Test.assert_policy_consistent(BrokenNotes, [member: member],
            secret: secret,
            open: open
          )
        end

      assert error.message =~ "Warden.Test.Ecto.BrokenNotes gives different answers in 1 cell(s)"
      assert error.message =~ "actor member, resource secret, action :read:"
      assert error.message =~ "allowed?/4 (hand-written)"
      assert error.message =~ "scope/4"
      refute error.message =~ "resource open"
      refute error.message =~ "sam"
    end

    test "the matrix fails on the same disagreement and names the cell" do
      secret = insert!(%Note{workspace_id: "t1", author_id: "abby", secret: true})
      member = context(%{id: "sam", memberships: %{"t1" => [:member]}})

      broken = %Matrix{
        authorizer: BrokenAuthz,
        repo: Repo,
        snapshot: snapshot_path(),
        actors: [member: member],
        resources: [secret: secret]
      }

      error = assert_raise ExUnit.AssertionError, fn -> Matrix.run!(broken, :update) end
      assert error.message =~ "actor member, resource secret, action :read:"
    end

    test "consistent policies return their cells" do
      rows = resources()

      cells =
        Warden.Test.assert_policy_consistent(
          Warden.Test.Ecto.Issues,
          [context(sam()), context(kim())],
          [rows[:issue]]
        )

      assert cells[{"actor 1", "row 1", :read}] == true
      assert cells[{"actor 2", "row 1", :read}] == false
      assert map_size(cells) == 8
    end

    test "a plain Warden.Policy gets the checks that apply" do
      docs = Doc.all()
      abby = People.context(People.abby())
      cells = Warden.Test.assert_policy_consistent(Docs, [abby: abby], docs)

      assert cells[{:abby, "row 1", :read}] == true
      assert cells[{:abby, "row 2", :read}] == false
    end
  end

  describe "completeness" do
    test "a policy without a resource fixture fails, naming the policy" do
      issue = insert!(%Issue{workspace_id: "t1"})
      incomplete = matrix([member: context(sam())], [issue: issue], snapshot_path())

      error = assert_raise ExUnit.AssertionError, fn -> Matrix.run!(incomplete, :update) end
      assert error.message =~ "Warden.Test.Ecto.Teams has no resource fixture"
      assert error.message =~ "Warden.Test.Ecto.Notes has no resource fixture"
      refute error.message =~ "Warden.Test.Ecto.Issues has no resource fixture"
    end

    test "a resource whose struct has no policy fails" do
      membership = insert!(%TeamMembership{team_id: 1, user_id: "sam"})

      stray =
        matrix([member: context(sam())], resources() ++ [membership: membership], snapshot_path())

      error = assert_raise ExUnit.AssertionError, fn -> Matrix.run!(stray, :update) end

      assert error.message =~
               "resource :membership is a Warden.Test.Ecto.TeamMembership, which has no policy"
    end
  end

  describe "snapshots" do
    test "--update writes a stable, sorted file" do
      rows = resources()
      actors = [member: context(sam()), owner: context(abby()), outsider: context(kim())]
      path = snapshot_path()

      first = Matrix.run!(matrix(actors, rows, path), :update)
      again = Matrix.run!(matrix(Enum.reverse(actors), Enum.reverse(rows), path), :update)

      assert first == again
      assert File.read!(path) == first
      assert ["# Warden policy matrix" <> _rest | _lines] = String.split(first, "\n")

      policies = for "policy " <> policy <- String.split(first, "\n"), do: policy
      assert policies == Enum.sort(policies)
      assert first =~ "resource  member  outsider  owner\n"

      assert Matrix.run!(matrix(actors, rows, path), :compare) == first
    end

    test "a difference prints the changed cells only" do
      rows = resources()
      path = snapshot_path()

      _written =
        Matrix.run!(matrix([member: context(sam()), guest: context(kim())], rows, path), :update)

      # The member loses its membership; the guest is now a member of t1.
      changed = [member: context(kim()), guest: context(sam())]

      error =
        assert_raise ExUnit.AssertionError, fn ->
          Matrix.run!(matrix(changed, rows, path), :compare)
        end

      [_title | lines] = error.message |> String.split("\n") |> Enum.drop(-1)

      assert error.message =~ ~r/differs from .* in \d+ cell\(s\)/
      assert "  resource issue, actor member: snapshot read,read_ids,write, now -" in lines
      assert "  resource issue, actor guest: snapshot -, now read,read_ids,write" in lines
      assert Enum.all?(lines, &(&1 =~ ~r/^  resource \w+, actor (member|guest)/))
      refute error.message =~ "client"
    end

    test "a missing snapshot names the command that writes it" do
      rows = resources()

      error =
        assert_raise ExUnit.AssertionError, fn ->
          Matrix.run!(matrix([member: context(sam())], rows, snapshot_path()), :compare)
        end

      assert error.message =~ "mix warden.matrix --update"
    end

    test "the table and the diff hold fixture names only, never subjects or row data" do
      rows = resources()
      path = snapshot_path()

      table =
        Matrix.run!(matrix([member: context(sam()), owner: context(abby())], rows, path), :update)

      error =
        assert_raise ExUnit.AssertionError, fn ->
          Matrix.run!(
            matrix([member: context(kim()), owner: context(abby())], rows, path),
            :compare
          )
        end

      for output <- [table, error.message],
          secret <- [
            "sam",
            "abby",
            "kim",
            "t1",
            "Secret",
            "Team Rocket",
            "Warden.Test.Ecto.Issue{"
          ] do
        refute output =~ secret, "#{inspect(secret)} in #{output}"
      end
    end
  end

  describe "GraphQL" do
    defp graphql!(object) do
      compile_schema(
        """
        #{object}

        query do
          field :issue, :issue do
            arg :id, non_null(:id)
            resolve fn %{id: id}, _resolution -> {:ok, Warden.Test.Repo.get(Warden.Test.Ecto.Issue, id)} end
          end

          field :comment, :comment do
            arg :id, non_null(:id)
            resolve fn %{id: id}, _resolution -> {:ok, Warden.Test.Repo.get(Warden.Test.Ecto.Comment, id)} end
          end
        end
        """,
        "authorizer: Warden.Test.Ecto.Authz"
      )
    end

    @comment "object :comment do\n  authorize can(Warden.Test.Ecto.Comments, :read)\n  redact_with Warden.Test.Ecto.CommentFields\n  field :id, :id\n  field :body, :string\nend"

    test "catches an object rule that disagrees with the policy" do
      schema =
        graphql!("""
        object :issue do
          warden_schema Warden.Test.Ecto.Issue
          authorize authenticated()
          field :id, :id
        end

        #{@comment}
        """)

      issue = insert!(%Issue{workspace_id: "t1", team_id: insert!(%Team{workspace_id: "t1"}).id})
      query_for = %{issue: "query($id: ID!) { issue(id: $id) { id } }"}

      cells = [
        authorizer: Authz,
        actors: [member: context(sam()), outsider: context(kim())],
        resources: [issue: issue]
      ]

      error =
        assert_raise ExUnit.AssertionError, fn ->
          AbsintheMatrix.assert_matrix_matches(schema, [query_for: query_for] ++ cells)
        end

      assert error.message =~
               "actor outsider, resource issue, type :issue: the policy denies :read, GraphQL returned the object"

      refute error.message =~ "actor member"
    end

    # A type over a redacted struct must declare `redact_with` (a compile-time rule), so
    # the field policy is bypassed here by a resolver that reloads the unredacted row.
    test "catches a field policy that GraphQL does not apply" do
      schema =
        graphql!("""
        object :issue do
          authorize can(Warden.Test.Ecto.Issues, :read)
          field :id, :id
        end

        object :comment do
          authorize can(Warden.Test.Ecto.Comments, :read)
          redact_with Warden.Test.Ecto.CommentFields
          field :id, :id

          field :body, :string do
            resolve fn comment, _args, _resolution ->
              {:ok, Warden.Test.Repo.get(Warden.Test.Ecto.Comment, comment.id).body}
            end
          end
        end
        """)

      issue = insert!(%Issue{workspace_id: "t1"})
      comment = insert!(%Comment{workspace_id: "t1", issue_id: issue.id, body: "Secret body"})
      query_for = %{comment: "query($id: ID!) { comment(id: $id) { id body } }"}
      guest = context(%{id: "gina", memberships: %{"t1" => [:guest]}})

      cells = [
        authorizer: Authz,
        actors: [guest: guest, member: context(sam())],
        resources: [comment: comment]
      ]

      error =
        assert_raise ExUnit.AssertionError, fn ->
          AbsintheMatrix.assert_matrix_matches(schema, [query_for: query_for] ++ cells)
        end

      assert error.message =~
               "actor guest, resource comment, type :comment: field :body is not redacted"

      refute error.message =~ "Secret body"
      refute error.message =~ "actor member"
    end
  end
end
