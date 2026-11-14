defmodule Warden.Test.Fields.Comment do
  @moduledoc false
  defstruct [:id, :workspace_id, :author_id, :trashed_at, body: "", anchor: nil, hidden: false]
end

defmodule Warden.Test.Fields.UserCard do
  @moduledoc false
  defstruct [:id, :tenant_id, :name, :timezone, :email]
end

defmodule Warden.Test.Fields.Issue do
  @moduledoc false
  defstruct [:id, :tenant_id, :title, :tag, comments: [], cards: []]
end

defmodule Warden.Test.Fields.Tag do
  @moduledoc false
  # Not registered: redaction leaves it alone, even when it looks like a comment.
  defstruct [:label, body: "tag body"]
end

defmodule Warden.Test.Fields.Authz do
  @moduledoc false
  # The authorizer of the field-policy tests. `live` and `readable` are batched and
  # report every call to `context.test_pid`; webhooks reach `live`, chat actors do not.
  use Warden.Authorizer,
    roles: [:staff],
    kinds: [:user, :agent, :webhook, :chat],
    tenant_roles: [:owner, :admin, :member, :guest],
    tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
    policies: [Warden.Test.Fields.Comments],
    fields: [
      Warden.Test.Fields.CommentFields,
      Warden.Test.Fields.UserCardFields,
      Warden.Test.Fields.IssueFields
    ],
    checks: [
      :author,
      live: [batch: true, system_kinds: [:webhook]],
      readable: [batch: true]
    ]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def kind(user, _context), do: Map.get(user, :kind, :user)

  @impl true
  def tenant_roles(user, tenant, context) do
    notify(context, {:tenant_roles, user.id, tenant})

    case context[:tenant_roles_fun] do
      nil -> user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
      fun -> fun.(user, tenant)
    end
  end

  @impl true
  def check(:author, %Warden.Check{actor: actor, value: value, context: context}) do
    notify(context, {:check, :author})
    author?(actor, value)
  end

  @impl true
  def check_many(name, checks) do
    context = List.first(checks).context
    notify(context, {:check_many, name, length(checks)})
    Enum.map(checks, &many(name, &1.value))
  end

  defp many(:live, value), do: is_map(value) and Map.get(value, :trashed_at) == nil
  defp many(:readable, value), do: is_map(value) and Map.get(value, :hidden) != true

  defp author?(%Warden.Actor{subject: %{id: id}}, %{author_id: id}), do: true
  defp author?(_actor, _value), do: false

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.Test.Fields.OpenAuthz do
  @moduledoc false
  # Lists the field policies that the compile tests define, so the checks after the
  # listing check can be reached. Never used at runtime.
  use Warden.Authorizer,
    roles: [:staff],
    kinds: [:user, :webhook],
    tenant_roles: [:member],
    policies: [Warden.Test.Fields.Comments],
    fields: Enum.map(1..11, &Module.concat(Warden.Test.Fields, "Open#{&1}")),
    checks: [live: [batch: true]]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(_user, _context), do: []

  @impl true
  def tenant_roles(_user, _tenant, _context), do: []

  @impl true
  def check_many(_name, checks), do: Enum.map(checks, fn _check -> false end)
end

defmodule Warden.Test.Fields.Comments do
  @moduledoc false
  use Warden.Policy,
    authorizer: Warden.Test.Fields.Authz,
    for: Warden.Test.Fields.Comment,
    actions: [:read],
    tenant: :workspace_id

  @impl true
  def allowed?(:read, _actor, comment, _context), do: comment.hidden != true
end

defmodule Warden.Test.Fields.CommentFields do
  @moduledoc false
  # A trashed comment's body and anchor are blank for everyone; the author's id is for
  # its author and members of the comment's workspace.
  use Warden.Fields, authorizer: Warden.Test.Fields.Authz, for: Warden.Test.Fields.Comment

  redact(:body, with: "", unless: check(:live))
  redact(:anchor, with: nil, unless: check(:live))
  redact(:author_id, with: nil, unless: any_of([check(:author), tenant_role(:member)]))
end

defmodule Warden.Test.Fields.UserCardFields do
  @moduledoc false
  # A guest must not see a member's timezone; email is for staff.
  use Warden.Fields, authorizer: Warden.Test.Fields.Authz, for: Warden.Test.Fields.UserCard

  redact(:timezone, with: nil, unless: tenant_role(:member))
  redact(:email, with: nil, unless: role(:staff))
end

defmodule Warden.Test.Fields.IssueFields do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.Test.Fields.Authz, for: Warden.Test.Fields.Issue

  redact(:title, with: "[private]", unless: tenant_role(:guest))
end

defmodule Warden.Test.Fields.People do
  @moduledoc false
  # Abby owns "t1" and is a guest in "t2"; Sam is a member of "t1"; Olivia is a guest in
  # "t1"; the staff user has no memberships.

  def abby, do: %{id: "abby", memberships: %{"t1" => [:owner], "t2" => [:guest]}}
  def sam, do: %{id: "sam", memberships: %{"t1" => [:member]}}
  def olivia, do: %{id: "olivia", memberships: %{"t1" => [:guest]}}
  def staff, do: %{id: "staff", roles: [:staff]}

  def context(user, extra \\ %{}), do: Map.merge(%{current_user: user, test_pid: self()}, extra)

  def actor(user, extra \\ %{}),
    do: Warden.actor(context(user, extra), authorizer: Warden.Test.Fields.Authz)
end

defmodule Warden.Test.Fields.DupAuthz do
  @moduledoc false
  # Lists two field policies for one struct, which redaction refuses.
  use Warden.Authorizer,
    roles: [:staff],
    fields: [Warden.Test.Fields.DupA, Warden.Test.Fields.DupB]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(_user, _context), do: []
end

defmodule Warden.Test.Fields.DupA do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.Test.Fields.DupAuthz, for: Warden.Test.Fields.Comment
  redact :body, with: "", unless: role(:staff)
end

defmodule Warden.Test.Fields.DupB do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.Test.Fields.DupAuthz, for: Warden.Test.Fields.Comment
  redact :anchor, with: nil, unless: role(:staff)
end

defmodule Warden.Test.Fields.NilAuthz do
  @moduledoc false
  # Lists a field policy that blanks a field with nil, for the non-null compile check.
  use Warden.Authorizer, roles: [:staff], fields: [Warden.Test.Fields.NilBodyFields]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(_user, _context), do: []
end

defmodule Warden.Test.Fields.NilBodyFields do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.Test.Fields.NilAuthz, for: Warden.Test.Fields.Comment
  redact :body, with: nil, unless: role(:staff)
  redact :anchor, with: nil, unless: role(:staff)
end
