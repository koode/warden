defmodule Warden.Ecto.AbsintheTest do
  use Warden.Test.EctoCase, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.Test.Ecto.{Authz, Comment, Issue, Issues, Team}

  defp run(document, context),
    do: Absinthe.run(document, Warden.Test.Ecto.GraphQL, context: context)

  defp graphql_ids(context) do
    {:ok, %{data: %{"issues" => issues}}} = run("{ issues { id } }", context)
    issues |> Enum.map(&String.to_integer(&1["id"])) |> Enum.sort()
  end

  setup do
    t1 = insert!(%Team{workspace_id: "t1"})
    t2 = insert!(%Team{workspace_id: "t2"})

    issues =
      for team <- [t1, t1, t2, t2],
          do:
            insert!(%Issue{workspace_id: team.workspace_id, team_id: team.id, author_id: "abby"})

    %{issues: issues}
  end

  test "a GraphQL list with a can/2 object rule equals the scope", %{issues: issues} do
    for user <- [abby(), sam(), kim()] do
      scoped = Issue |> WardenEcto.scope(context(user), :read, authorizer: Authz) |> all_ids()
      assert graphql_ids(context(user)) == scoped
    end

    assert [_first, _second, _third, _fourth] = issues
  end

  test "can/2 over a list runs one query per policy and tenant" do
    user = Map.put(sam(), :memberships, %{"t1" => [:member], "t2" => [:member]})
    {ids, count} = count_queries(fn -> graphql_ids(context(user)) end)

    # One query for the resolver, one per tenant for the object rule.
    assert [_first, _second, _third, _fourth] = ids
    assert count == 3

    {_ids, count} = count_queries(fn -> graphql_ids(context(sam())) end)
    assert count == 2
  end

  test "Warden.filter/4 with can/2 asks the policy once per list" do
    issues = Repo.all(Issue)
    rule = Warden.Rule.can(Issues, :read)

    {filtered, count} =
      count_queries(fn -> Warden.filter(context(sam()), rule, issues, authorizer: Authz) end)

    assert ids(filtered) == issues |> Enum.filter(&(&1.workspace_id == "t1")) |> ids()
    assert count == 1
  end

  test "can(..., arg: path) decides before the resolver", %{
    issues: [t1_issue, _other, t2_issue, _last]
  } do
    document = """
    mutation($id: ID!) { renameIssue(id: $id, title: "renamed") { id title } }
    """

    key = %Warden.Credential{method: :api_key, scopes: ["issues:write"]}
    allowed = context(sam(), %{credential: key})

    {:ok, result} =
      Absinthe.run(document, Warden.Test.Ecto.GraphQL,
        context: allowed,
        variables: %{"id" => "#{t1_issue.id}"}
      )

    assert result.data["renameIssue"]["title"] == "renamed"
    assert_received {:resolved, :rename_issue, _id}

    {:ok, result} =
      Absinthe.run(document, Warden.Test.Ecto.GraphQL,
        context: allowed,
        variables: %{"id" => "#{t2_issue.id}"}
      )

    assert result.data["renameIssue"] == nil
    assert [%{message: "Forbidden"}] = result.errors
    refute_received {:resolved, :rename_issue, _id}
    assert Repo.get!(Issue, t2_issue.id).title == ""

    read_only = context(sam(), %{credential: %{key | scopes: ["issues:read"]}})

    {:ok, result} =
      Absinthe.run(document, Warden.Test.Ecto.GraphQL,
        context: read_only,
        variables: %{"id" => "#{t1_issue.id}"}
      )

    assert [%{message: "Forbidden"}] = result.errors
    refute_received {:resolved, :rename_issue, _id}
  end

  test "a page of can/2 object rules reads tenants once and each tenant's roles once",
       %{issues: [t1_issue, _second, t2_issue, _fourth]} do
    comment = insert!(%Comment{workspace_id: "t1", issue_id: t1_issue.id, body: "b"})

    document = """
    {
      issues { id title }
      first: issue(id: "#{t1_issue.id}") { id }
      second: issue(id: "#{t2_issue.id}") { id }
      comment(id: "#{comment.id}") { id body }
    }
    """

    {:ok, %{data: data}} = run(document, context(abby()))
    assert [_first | _rest] = data["issues"]

    {:messages, messages} = Process.info(self(), :messages)
    tenant_reads = for {:tenants, "abby"} <- messages, do: :tenants
    role_reads = for {:tenant_roles, "abby", tenant} <- messages, do: tenant

    assert tenant_reads in [[], [:tenants]], "tenants/2 ran #{length(tenant_reads)} times"
    assert role_reads == Enum.uniq(role_reads), "tenant_roles/3 ran twice for a tenant"
  end
end
