defmodule Warden.RedteamV03.IdsAuthz do
  @moduledoc false
  # Private teams are readable only while the context is `active`; issues are readable
  # through their team's id list (`resolve: :ids`), so the parent scope depends on the
  # context.
  use Warden.Authorizer,
    roles: [:staff],
    kinds: [:user, :agent],
    tenant_roles: [:member],
    policies: [Warden.RedteamV03.ActiveTeams, Warden.RedteamV03.TeamIssues],
    checks: [:active]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def kind(user, _context), do: Map.get(user, :kind, :user)

  @impl true
  def tenant_roles(user, tenant, _context),
    do: user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])

  @impl true
  def tenants(actor, _context),
    do: actor.subject |> Map.get(:memberships, %{}) |> Map.keys()

  @impl true
  def check(:active, %Warden.Check{context: context}), do: Map.get(context, :active, true)
end

defmodule Warden.RedteamV03.ActiveTeams do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV03.IdsAuthz,
    schema: Warden.Test.Ecto.Team,
    as: :team,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  # Public teams for members; every team while the context is `active`.
  allow :read, rule: tenant_role(:member), where: [private: false]
  allow :read, rule: check(:active)
end

defmodule Warden.RedteamV03.TeamIssues do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV03.IdsAuthz,
    schema: Warden.Test.Ecto.Issue,
    as: :issue,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  allow :read, through: {:team, :read, resolve: :ids}
end

defmodule Warden.RedteamV03.IdsCacheTest do
  # `Warden.Ecto.preload_ids/4` caches a parent's ids in the actor. Every test asserts
  # the secure behaviour: a failing test is an open hole.
  use Warden.Test.EctoCase, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.RedteamV03.IdsAuthz
  alias Warden.Test.Ecto.{Issue, Team}

  @user %{id: "sam", memberships: %{"t1" => [:member], "t2" => [:member]}}

  setup do
    t1 = insert!(%Team{workspace_id: "t1"})
    t2 = insert!(%Team{workspace_id: "t2", private: true})
    i1 = insert!(%Issue{workspace_id: "t1", team_id: t1.id, author_id: "abby"})
    i2 = insert!(%Issue{workspace_id: "t2", team_id: t2.id, author_id: "abby"})
    %{i1: i1, i2: i2}
  end

  defp ids_actor(user, extra \\ %{}) do
    context = Map.merge(%{current_user: user}, extra)
    Warden.actor(context, authorizer: IdsAuthz)
  end

  defp scoped_ids(actor, opts) do
    Issue
    |> WardenEcto.scope(actor, :read, opts)
    |> all_ids()
  end

  # Goal 8: the scope must come from the policy, under the context it is asked with.
  # The ids are cached under a key that names the actor (its own context included) but
  # not the context the call runs with, so ids read under `active: true` (every team)
  # are reused by a later scope under `active: false` (public teams only).
  test "ids preloaded under one context are not reused by a scope under another", world do
    actor = ids_actor(@user, %{active: false})
    assert scoped_ids(actor, []) == [world.i1.id]

    preloaded = WardenEcto.preload_ids(actor, Team, :read, context: %{active: true})
    assert scoped_ids(preloaded, []) == [world.i1.id]
  end

  test "ids of one tenant are never used for another tenant", world do
    actor = ids_actor(Map.put(@user, :memberships, %{"t1" => [:member]}))
    preloaded = WardenEcto.preload_ids(actor, Team, :read, tenant: "t1")
    assert scoped_ids(preloaded, tenant: "t2") == []
    assert scoped_ids(preloaded, tenant: "t1") == [world.i1.id]
  end

  test "a delegated actor's cache never widens either side", world do
    agent = ids_actor(%{id: "olivia", kind: :agent, memberships: %{"t1" => [:member]}})
    principal = ids_actor(%{id: "kim", memberships: %{"t2" => [:member]}}, %{active: true})

    # The principal alone preloads, then delegates: the delegated actor carries a copy
    # with a new instance, so its key misses and the AND of both sides is computed.
    principal = WardenEcto.preload_ids(principal, Team, :read)
    delegated = Warden.on_behalf_of(agent, principal)
    assert scoped_ids(delegated, []) == []

    delegated = WardenEcto.preload_ids(delegated, Team, :read)
    assert scoped_ids(delegated, []) == []

    # The agent side's ids are its own: a rebuilt agent sees t1 only.
    assert scoped_ids(agent, []) == [world.i1.id]
  end

  test "a credential bound to one tenant ignores ids cached before binding", world do
    actor = ids_actor(@user)
    preloaded = WardenEcto.preload_ids(actor, Team, :read)
    bound = %{preloaded | credential: %Warden.Credential{method: :token, tenant: "t1"}}
    assert scoped_ids(bound, []) == [world.i1.id]
  end
end
