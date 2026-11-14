defmodule Warden.Test.Ecto.Authz do
  @moduledoc false
  # The authorizer of the Ecto suite. Users are maps with `memberships` (tenant => tenant
  # roles); `tenants/2` lists the tenants they have memberships in plus `extra_tenants`.
  # Callbacks report to `context.test_pid`, so tests can count them.
  use Warden.Authorizer,
    roles: [:instance_admin],
    kinds: [:user, :agent, :webhook, :job],
    tenant_roles: [:owner, :admin, :member, :guest],
    tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
    credential_scopes: ["issues:read", "issues:write"],
    policies: [
      Warden.Test.Ecto.Teams,
      Warden.Test.Ecto.Issues,
      Warden.Test.Ecto.Comments,
      Warden.Test.Ecto.Projects,
      Warden.Test.Ecto.Summaries,
      Warden.Test.Ecto.OauthClients,
      Warden.Test.Ecto.Notes
    ],
    fields: [Warden.Test.Ecto.CommentFields],
    checks: [:active]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def kind(user, _context), do: Map.get(user, :kind, :user)

  @impl true
  def credential(context), do: context[:credential]

  @impl true
  def tenant_roles(user, tenant, context) do
    notify(context, {:tenant_roles, user.id, tenant})
    user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
  end

  @impl true
  def tenants(actor, context) do
    notify(context, {:tenants, actor.subject.id})
    subject = actor.subject
    memberships = subject |> Map.get(:memberships, %{}) |> Map.keys()
    memberships ++ Map.get(subject, :extra_tenants, [])
  end

  @impl true
  def check(:active, %Warden.Check{context: context}) do
    notify(context, {:check, :active})
    Map.get(context, :active, true)
  end

  @spec notify(map, term) :: term
  def notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  def notify(_context, _message), do: :ok
end

defmodule Warden.Test.Ecto.Teams do
  @moduledoc false
  # Public teams for members, private teams through a membership row, webhooks within
  # their bounds. The last clause carries a literal that would break a query if it were
  # not a parameter.
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.Team,
    as: :team,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read],
    system_kinds: [:webhook]

  alias Warden.Test.Ecto.TeamMembership

  allow :read, rule: tenant_role(:member), where: [private: false]
  allow :read, rule: tenant_role(:guest), member_of: {TeamMembership, :team_id, :user_id}
  allow :read, rule: kind(:webhook), within: {:team_ids, :id}
  allow :read, rule: tenant_role(:owner), where: [name: "o'brien\"; DROP TABLE teams; --"]
end

defmodule Warden.Test.Ecto.Issues do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.Issue,
    as: :issue,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read, :read_trashed, :write],
    write_actions: [:write],
    system_kinds: [:webhook]

  alias Warden.Test.Ecto.Share

  allow :read, through: :team, if_nil: :tenant, where: [trashed_at: nil]

  allow :read,
    grant: {Share, :issue_id, :grantee_id, expires_at: :expires_at},
    where: [trashed_at: nil]

  allow :read, rule: kind(:agent), within: {:issue_ids, :id}
  allow :read, rule: kind(:webhook), through: :team, where: [trashed_at: nil]
  allow :read_trashed, tenant_role(:admin)
  allow :write, rule: tenant_role(:member), through: {:team, :read}, where: [trashed_at: nil]
  allow :write, actor_in: [:author_id], where: [trashed_at: nil]
  requires :write, credential_scope("issues:write")
end

defmodule Warden.Test.Ecto.Comments do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.Comment,
    as: :comment,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  import Ecto.Query, only: [dynamic: 2]

  allow :read, through: :issue

  allow :read,
    rule: tenant_role(:admin),
    when: fn actor, _tenant, _context ->
      dynamic([comment: comment], comment.author_id == ^actor.subject.id)
    end
end

defmodule Warden.Test.Ecto.Projects do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.Project,
    as: :project,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  alias Warden.Test.Ecto.ProjectMember

  allow :read, rule: tenant_role(:member), none: :project_teams
  allow :read, through_any: :teams
  allow :read, rule: tenant_role(:guest), actor_in: [:lead_id, :creator_id]
  allow :read, rule: tenant_role(:guest), member_of: {ProjectMember, :project_id, :user_id}
  requires :read, check(:active)
end

defmodule Warden.Test.Ecto.Summaries do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.Summary,
    as: :summary,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  allow :read,
    through_type:
      {:subject_type, :subject_id,
       %{
         "project" => Warden.Test.Ecto.Projects,
         "team" => Warden.Test.Ecto.Teams,
         "comment" => Warden.Test.Ecto.Comments
       }}
end

defmodule Warden.Test.Ecto.OauthClients do
  @moduledoc false
  # Clients of a workspace for its admins; clients without a workspace (a `NULL` tenant)
  # for their owner only.
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.OauthClient,
    as: :client,
    tenant: :workspace_id,
    null_tenant: true,
    repo: Warden.Test.Repo,
    actions: [:read]

  allow :read, rule: tenant_role(:admin)
  allow :read, actor_in: [:owner_id]
end

defmodule Warden.Test.Ecto.Notes do
  @moduledoc false
  # A hand-written scope with a matching allowed?/4. `context.scope_result` replaces the
  # scope's result, to test what Warden does with a bad one.
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.Authz,
    schema: Warden.Test.Ecto.Note,
    as: :note,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read, :write]

  import Ecto.Query, only: [dynamic: 2]

  alias Warden.Actor
  alias Warden.Test.Ecto.{Authz, Note}

  @impl true
  def scope(action, %Actor{} = actor, tenant, context) do
    Authz.notify(context, {:scope, action, tenant})

    case Map.fetch(context, :scope_result) do
      {:ok, result} -> result
      :error -> note_scope(action, actor, tenant, context)
    end
  end

  @impl true
  def allowed?(action, %Actor{} = actor, %Note{} = note, context) do
    Authz.notify(context, {:allowed?, action, note.id})
    author? = author_id(actor) != nil and note.author_id == author_id(actor)

    case action do
      :read -> member?(actor, note.workspace_id, context) and (not note.secret or author?)
      :write -> author?
    end
  end

  defp note_scope(:read, actor, tenant, context) do
    id = author_id(actor)

    cond do
      not member?(actor, tenant, context) -> false
      id == nil -> dynamic([note: note], note.secret == false)
      true -> dynamic([note: note], note.secret == false or note.author_id == ^id)
    end
  end

  defp note_scope(:write, actor, _tenant, _context) do
    case author_id(actor) do
      nil -> false
      id -> dynamic([note: note], note.author_id == ^id)
    end
  end

  defp member?(actor, tenant, context) do
    {roles, _actor} = Actor.tenant_roles(actor, tenant, context)
    MapSet.size(roles) > 0
  end

  defp author_id(%Actor{system?: false, subject: %{id: id}}), do: id
  defp author_id(%Actor{}), do: nil
end

defmodule Warden.Test.Ecto.People do
  @moduledoc false
  # Abby owns "t1" and is a guest in "t2"; Sam is a member of "t1"; Olivia is an agent
  # with a guest membership in "t1"; Kim is a member of "t2" only.

  @authorizer Warden.Test.Ecto.Authz

  def abby, do: %{id: "abby", memberships: %{"t1" => [:owner], "t2" => [:guest]}}
  def sam, do: %{id: "sam", memberships: %{"t1" => [:member]}}
  def olivia, do: %{id: "olivia", kind: :agent, memberships: %{"t1" => [:guest]}}
  def kim, do: %{id: "kim", memberships: %{"t2" => [:member]}}

  def context(user, extra \\ %{}), do: Map.merge(%{current_user: user, test_pid: self()}, extra)

  def actor(user, extra \\ %{}), do: Warden.actor(context(user, extra), authorizer: @authorizer)

  def webhook(opts), do: Warden.system_actor(@authorizer, [kind: :webhook] ++ opts)
end

defmodule Warden.Test.Ecto.CommentFields do
  @moduledoc false
  # Guests do not see comment bodies.
  use Warden.Fields, authorizer: Warden.Test.Ecto.Authz, for: Warden.Test.Ecto.Comment

  redact :body, with: "", unless: tenant_role(:member)
end

defmodule Warden.Test.Ecto.BrokenAuthz do
  @moduledoc false
  # An authorizer with one policy whose hand-written allowed?/4 disagrees with its
  # scope/4 for secret notes, to prove the consistency checks catch it.
  use Warden.Authorizer,
    roles: [:instance_admin],
    tenant_roles: [:member],
    policies: [Warden.Test.Ecto.BrokenNotes]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(_user, _context), do: []

  @impl true
  def tenant_roles(user, tenant, _context),
    do: user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])

  @impl true
  def tenants(actor, _context), do: actor.subject |> Map.get(:memberships, %{}) |> Map.keys()
end

defmodule Warden.Test.Ecto.BrokenNotes do
  @moduledoc false
  use Warden.Ecto.Policy,
    authorizer: Warden.Test.Ecto.BrokenAuthz,
    schema: Warden.Test.Ecto.Note,
    as: :note,
    tenant: :workspace_id,
    repo: Warden.Test.Repo,
    actions: [:read]

  import Ecto.Query, only: [dynamic: 2]

  @impl true
  def scope(:read, _actor, _tenant, _context), do: dynamic([note: note], note.secret == false)

  # Wrong on purpose: it forgets that secret notes are hidden.
  @impl true
  def allowed?(:read, _actor, _note, _context), do: true
end
