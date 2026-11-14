defmodule Warden.RedteamV2Ecto.Authz do
  @moduledoc false
  # A second authorizer over the tables of the Ecto suite, with policies built to probe one
  # clause each: `through_any:` over a has_many, `within:` on a nullable field, `grant:`
  # through a table name, and a hand-written `allowed_many/4`.
  use Warden.Authorizer,
    roles: [:instance_admin],
    kinds: [:user, :agent, :webhook],
    tenant_roles: [:owner, :admin, :member, :guest],
    tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
    policies: [
      Warden.RedteamV2Ecto.Issues,
      Warden.RedteamV2Ecto.Comments,
      Warden.RedteamV2Ecto.Teams,
      Warden.RedteamV2Ecto.Notes
    ]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(_user, _context), do: []

  @impl true
  def kind(user, _context), do: Map.get(user, :kind, :user)

  @impl true
  def credential(context), do: context[:credential]

  @impl true
  def tenant_roles(user, tenant, _context) do
    user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
  end

  @impl true
  def tenants(actor, context) do
    case Map.fetch(context, :tenants_result) do
      {:ok, result} -> result
      :error -> actor.subject |> Map.get(:memberships, %{}) |> Map.keys()
    end
  end
end

defmodule Warden.RedteamV2Ecto.Issues do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV2Ecto.Authz,
    schema: Warden.Test.Ecto.Issue,
    as: :issue,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  allow(:read, through_any: :comments)
  allow(:read, rule: kind(:agent), within: {:team_ids, :team_id})
end

defmodule Warden.RedteamV2Ecto.Comments do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV2Ecto.Authz,
    schema: Warden.Test.Ecto.Comment,
    as: :comment,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  allow(:read, actor_in: [:author_id])
end

defmodule Warden.RedteamV2Ecto.Teams do
  @moduledoc false
  # The grant table is named, not a schema, and its `expires_at` is a `timestamptz`.
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV2Ecto.Authz,
    schema: Warden.Test.Ecto.Team,
    as: :team,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  allow(:read, grant: {"rt_team_grants", :team_id, :grantee_id, expires_at: :expires_at})
end

defmodule Warden.RedteamV2Ecto.Notes do
  @moduledoc false
  # A hand-written `allowed_many/4` whose answer list is longer than the notes it is asked
  # about when `context.extra_answers` is set.
  use Warden.Ecto.Policy,
    authorizer: Warden.RedteamV2Ecto.Authz,
    schema: Warden.Test.Ecto.Note,
    as: :note,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  @impl true
  def scope(:read, _actor, _tenant, _context), do: false

  @impl true
  def allowed_many(:read, _actor, notes, context) do
    answers = Enum.map(notes, fn _note -> false end)
    answers ++ Map.get(context, :extra_answers, [])
  end
end

defmodule Warden.RedteamV2Ecto.People do
  @moduledoc false
  # Actors of `Warden.RedteamV2Ecto.Authz`: Sam is a member of "t1", Olivia an agent with
  # a guest membership in "t1".

  @authorizer Warden.RedteamV2Ecto.Authz

  def sam, do: %{id: "sam", memberships: %{"t1" => [:member]}}
  def olivia, do: %{id: "olivia", kind: :agent, memberships: %{"t1" => [:guest]}}

  def context(user, extra \\ %{}), do: Map.merge(%{current_user: user}, extra)

  def actor(user, extra \\ %{}), do: Warden.actor(context(user, extra), authorizer: @authorizer)
end
