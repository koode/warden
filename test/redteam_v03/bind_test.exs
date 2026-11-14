defmodule Warden.RedteamV03.BindAuthz do
  @moduledoc false
  # Comments are readable by their author, through a fragment whose SQL carries a comment
  # with an apostrophe (a documented, harmless-looking SQL comment).
  use Warden.Authorizer,
    roles: [:staff],
    tenant_roles: [:member],
    policies: [Warden.RedteamV03.OwnComments]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def tenant_roles(user, tenant, _context),
    do: user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])

  @impl true
  def tenants(actor, _context),
    do: actor.subject |> Map.get(:memberships, %{}) |> Map.keys()
end

defmodule Warden.RedteamV03.OwnComments do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV03.BindAuthz,
    schema: Warden.Test.Ecto.Comment,
    as: :comment,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  import Ecto.Query, only: [dynamic: 2]

  allow :read,
    rule: tenant_role(:member),
    when: fn actor, _tenant, _context ->
      dynamic(
        [comment: comment],
        fragment("? /* the author's own */ = ?", comment.author_id, ^actor.subject.id)
      )
    end
end

defmodule Warden.RedteamV03.BindTest do
  # `Warden.Ecto.to_sql/4` with `param_offset:` and `bind:`. Every test asserts the
  # secure behaviour: a failing test is an open hole.
  use Warden.Test.EctoCase, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.Ecto.Placeholders
  alias Warden.RedteamV03.BindAuthz
  alias Warden.Test.Ecto.{Comment, OauthClient}

  @sam %{id: "sam", memberships: %{"t1" => [:member]}}

  defp bind_actor(user), do: Warden.actor(%{current_user: user}, authorizer: BindAuthz)

  # Goal 1/8 for the raw-SQL path: every placeholder of the scope must end up pointing at
  # the scope's own value. The renumbering walks single and double quotes only, so an
  # apostrophe inside a SQL comment of a policy fragment flips it into "string" mode and
  # the scope's later placeholders keep their old numbers: they then point at the host
  # statement's own parameters, which the end user may control.
  describe "renumbering through SQL a fragment may contain" do
    test "an apostrophe in a block comment does not stop renumbering, end to end" do
      own = insert!(%Comment{workspace_id: "t1", author_id: "sam", body: "mine"})
      # The end user types "abby" as the search term and reads abby's comment.
      _other = insert!(%Comment{workspace_id: "t1", author_id: "abby", body: "abby's"})
      actor = bind_actor(@sam)

      ids = from(comment in Comment, select: comment.id)
      {sql, params} = WardenEcto.to_sql(ids, actor, :read, param_offset: 2, bind: %{1 => "sam"})

      # $1 is the actor's id (bound), $2 a search term typed by the end user.
      host = """
      SELECT c.id FROM comments AS c \
      WHERE (c.author_id = $1 OR c.body <> $2) AND c.id IN (#{sql}) ORDER BY c.id\
      """

      %{rows: rows} = Repo.query!(host, ["sam", "abby" | params])
      assert List.flatten(rows) == [own.id], "scope SQL: #{sql}"
    end

    test "without bind:, the same fragment fails closed rather than reading a host value" do
      insert!(%Comment{workspace_id: "t1", author_id: "abby", body: "abby's"})
      ids = from(comment in Comment, select: comment.id)
      {sql, params} = WardenEcto.to_sql(ids, bind_actor(@sam), :read, param_offset: 2)

      host = """
      SELECT c.id FROM comments AS c \
      WHERE (c.author_id = $1 OR c.body <> $2) AND c.id IN (#{sql})\
      """

      result =
        try do
          Repo.query!(host, ["sam", "abby" | params]).rows
        rescue
          error -> {:error, error.__struct__}
        end

      assert result == [] or match?({:error, _module}, result), "scope SQL: #{sql}"
    end

    test "an apostrophe in a line comment does not stop renumbering" do
      sql = "SELECT 1 WHERE a = $1 -- the author's\n AND b = $2"
      assert Placeholders.shift(sql, 2) == "SELECT 1 WHERE a = $3 -- the author's\n AND b = $4"
    end

    test "a dollar-quoted string does not stop renumbering" do
      sql = "SELECT 1 WHERE a = $$it's$$ AND b = $1"

      assert Placeholders.bind(sql, ["x"], 1, %{}) ==
               {"SELECT 1 WHERE a = $$it's$$ AND b = $2", ["x"]}
    end

    test "an escape string with a backslash-quoted apostrophe does not stop renumbering" do
      sql = ~S|SELECT 1 WHERE a = E'it\'s' AND b = $1|
      assert Placeholders.shift(sql, 1) == ~S|SELECT 1 WHERE a = E'it\'s' AND b = $2|
    end
  end

  describe "bind: keys and values" do
    test "keys at or past the offset, zero or negative are refused" do
      actor = bind_actor(@sam)

      for bad <- [%{3 => "sam"}, %{0 => "sam"}, %{-1 => "sam"}, %{"1" => "sam"}, %{1.0 => "sam"}] do
        assert_raise ArgumentError, fn ->
          WardenEcto.to_sql(Comment, actor, :read, param_offset: 2, bind: bad)
        end
      end
    end

    test "the error for a bad key never shows a bound value" do
      actor = bind_actor(@sam)

      error =
        assert_raise ArgumentError, fn ->
          WardenEcto.to_sql(Comment, actor, :read, param_offset: 1, bind: %{2 => "s3cr3t"})
        end

      refute Exception.message(error) =~ "s3cr3t"
    end

    test "a host value of another tenant is never shared with the scope's tenant" do
      insert!(%OauthClient{workspace_id: "t1", owner_id: "kim"})
      insert!(%OauthClient{workspace_id: "t2", owner_id: "kim"})
      ids = from(client in OauthClient, select: client.id)
      opts = [param_offset: 1, bind: %{1 => "t2"}, tenant: "t1"]
      {sql, params} = WardenEcto.to_sql(ids, actor(abby()), :read, opts)

      host = """
      SELECT c.workspace_id FROM oauth_clients AS c \
      WHERE $1::text IS NOT NULL AND c.id IN (#{sql})\
      """

      %{rows: rows} = Repo.query!(host, ["t2" | params])
      assert List.flatten(rows) == ["t1"]
    end

    test "a value equal but not identical (1 vs 1.0, charlist vs string) is never shared" do
      sql = "SELECT 1 WHERE a = $1 AND b = $2"

      assert Placeholders.bind(sql, [1, "t1"], 2, %{1 => 1.0, 2 => ~c"t1"}) ==
               {"SELECT 1 WHERE a = $3 AND b = $4", [1, "t1"]}
    end
  end
end
