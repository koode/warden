defmodule Warden.Test.Reuse.Team do
  @moduledoc false
  defstruct [:id, :owner_id, :tenant, :name, :secret, flag: false]
end

defmodule Warden.Test.Reuse.Issue do
  @moduledoc false
  defstruct [:id, :owner_id, :tenant, :title, :body, :team, :assignee, flag: false]
end

defmodule Warden.Test.Reuse.User do
  @moduledoc false
  defstruct [:id, :name, :tenant]
end

defmodule Warden.Test.Reuse.Authz do
  @moduledoc false
  # The authorizer of the decision reuse suite. Every check and policy call reports to
  # `context.test_pid`, so a test can count the evaluations; every denial too, so a test
  # can compare the denials of two runs.
  #
  # Checks with `per_object: true` read only what they may: the actor, the value and the
  # context. `peek_field` and `peek_args` read the field and its arguments (they decide
  # per field), `sneaky` declares `per_object: true` and still tries to read the field,
  # and `single_owns` is batched with `single: true`, so it is never reused.
  use Warden.Authorizer,
    roles: [:admin, :member],
    permissions: ["read"],
    kinds: [:user, :bot],
    tenant_roles: [:owner, :viewer],
    tenant_role_hierarchy: %{owner: [:viewer]},
    credential_scopes: ["read"],
    policies: [Warden.Test.Reuse.TeamPolicy, Warden.Test.Reuse.IssuePolicy],
    checks: [
      owns: [per_object: true],
      flag_on: [per_object: true],
      ctx_allows: [per_object: true],
      sneaky: [per_object: true],
      loader_peek: [per_object: true],
      revoked: [per_object: true],
      many_owns: [batch: true, per_object: true],
      single_owns: [batch: true, single: true, per_object: true],
      peek_field: [],
      peek_args: []
    ]

  alias Warden.Check

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def permissions(user, _context), do: Map.get(user, :perms, [])

  @impl true
  def kind(user, _context), do: Map.get(user, :kind, :user)

  @impl true
  def credential(context), do: context[:credential]

  @impl true
  def tenant_of(%{tenant: tenant}), do: tenant
  def tenant_of(_value), do: nil

  @impl true
  def tenant_roles(user, tenant, context) do
    notify(context, {:tenant_roles, tenant})
    user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
  end

  @impl true
  def check(name, %Check{context: context} = check) do
    notify(context, {:check, name})
    single(name, check)
  end

  @impl true
  def check_many(name, [%Check{context: context} | _rest] = checks) do
    notify(context, {:check_many, name, length(checks)})
    Enum.map(checks, &many(name, &1))
  end

  # `single_owns` answers a list differently from a single value (`check/2`), so a
  # decision from a list never stands in for a single one.
  defp many(:single_owns, %Check{actor: actor, value: value}),
    do: owner?(actor, value) or (is_map(value) and Map.get(value, :flag) == true)

  defp many(name, check), do: single(name, check)

  defp single(name, %Check{actor: actor, value: value})
       when name in [:owns, :many_owns, :single_owns],
       do: owner?(actor, value)

  defp single(:flag_on, %Check{value: value}), do: is_map(value) and Map.get(value, :flag) == true

  defp single(:ctx_allows, %Check{value: value, context: context}),
    do: is_map(value) and Map.get(value, :id) in Map.get(context, :allow, [])

  # Declares `per_object: true` but decides by the field, as `peek_field` does. In an
  # object rule it never gets the field, so it decides the same everywhere, with or
  # without decision reuse; if it got the field, reuse would hand one field's decision
  # to another.
  defp single(:sneaky, %Check{field: field, context: context}),
    do: field not in Map.get(context, :hidden_fields, [])

  # Declares `per_object: true` and reads `:loader`, which such a check never gets.
  defp single(:loader_peek, %Check{context: context}), do: Map.get(context, :loader) == nil

  defp single(:revoked, %Check{value: value, context: context}) do
    revoked = context |> Map.fetch!(:revoked) |> Agent.get(& &1)
    is_map(value) and Map.get(value, :id) not in revoked
  end

  defp single(:peek_field, %Check{field: field, context: context}),
    do: field not in Map.get(context, :hidden_fields, [])

  defp single(:peek_args, %Check{args: args}), do: Map.get(args, :tag) != "hidden"

  def owner?(%Warden.Actor{subject: %{id: id}}, %{owner_id: id}), do: true
  def owner?(_actor, _value), do: false

  @impl true
  def deny(%Warden.Denial{} = denial) do
    notify(denial.actor.context, {:denial, comparable(denial)})

    case denial.actor.context[:deny_mode] do
      :null -> :null
      _error -> {:error, %{message: "Forbidden", code: "FORBIDDEN"}}
    end
  end

  # Everything a denial says, without the actor's cache (what it has read so far).
  defp comparable(denial) do
    denial
    |> Map.from_struct()
    |> Map.delete(:actor)
  end

  def notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  def notify(_context, _message), do: :ok
end

defmodule Warden.Test.Reuse.TeamPolicy do
  @moduledoc false
  use Warden.Policy,
    authorizer: Warden.Test.Reuse.Authz,
    for: Warden.Test.Reuse.Team,
    actions: [:read],
    tenant: :tenant

  alias Warden.Test.Reuse.Authz

  @impl true
  def allowed?(:read, actor, team, context) do
    Authz.notify(context, {:policy, :team})
    # Reads the whole context, `:loader` included, as a policy may.
    Map.get(context, :loader) != 2 and (team.flag or Authz.owner?(actor, team))
  end
end

defmodule Warden.Test.Reuse.IssuePolicy do
  @moduledoc false
  use Warden.Policy,
    authorizer: Warden.Test.Reuse.Authz,
    for: Warden.Test.Reuse.Issue,
    actions: [:read],
    tenant: :tenant

  alias Warden.Test.Reuse.Authz

  @impl true
  def allowed?(:read, actor, issue, context), do: hd(allowed_many(:read, actor, [issue], context))

  @impl true
  def allowed_many(:read, actor, issues, context) do
    Authz.notify(context, {:policy_many, :issue, length(issues)})
    Enum.map(issues, &(&1.flag or Authz.owner?(actor, &1)))
  end
end

defmodule Warden.Test.Reuse.Bump do
  @moduledoc false
  # Changes the context for every field after this one, as a resolver that grants or
  # revokes access in the middle of a document would: drops the parent from `allow`, and
  # toggles the parent's team, so the team is allowed under one parent and not under the
  # next.
  @behaviour Absinthe.Middleware

  @impl true
  def call(%Absinthe.Resolution{source: source, context: context} = resolution, _options) do
    allow = context |> Map.get(:allow, []) |> List.delete(source.id) |> toggle(team_id(source))
    context = Map.put(context, :allow, allow)
    %{resolution | context: context, state: :resolved, value: "bumped"}
  end

  defp team_id(%{team: %{id: id}}), do: id
  defp team_id(_source), do: nil

  defp toggle(allow, nil), do: allow

  defp toggle(allow, id) do
    if id in allow, do: List.delete(allow, id), else: [id | allow]
  end
end

defmodule Warden.Test.Reuse.Touch do
  @moduledoc false
  # Replaces `:loader` in the context for every field after this one, as Absinthe's
  # Dataloader plugin does on every resolution pass.
  @behaviour Absinthe.Middleware

  @impl true
  def call(%Absinthe.Resolution{context: context} = resolution, _options) do
    context = Map.put(context, :loader, Map.get(context, :loader, 0) + 1)
    %{resolution | context: context, state: :resolved, value: "touched"}
  end
end

defmodule Warden.Test.Reuse.Resolvers do
  @moduledoc false
  def root(key), do: fn _args, resolution -> {:ok, Map.fetch!(resolution.context.data, key)} end

  def by_id(key) do
    fn %{id: id}, resolution ->
      found = resolution.context.data |> Map.fetch!(key) |> Enum.find(&(to_string(&1.id) == id))
      {:ok, found}
    end
  end

  def team_issues(team, _args, resolution) do
    issues = Enum.filter(resolution.context.data.issues, &(&1.team && &1.team.id == team.id))
    {:ok, issues}
  end

  def node_type(%Warden.Test.Reuse.Issue{}, _resolution), do: :issue
  def node_type(%Warden.Test.Reuse.Team{}, _resolution), do: :team
  def node_type(_value, _resolution), do: nil
end
