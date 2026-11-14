defmodule Warden.RedteamV2.Doc do
  @moduledoc false
  defstruct [:id, :workspace_id, :owner_id, body: "", public: false, visible: true]
end

defmodule Warden.RedteamV2.Note do
  @moduledoc false
  defstruct [:id, :workspace_id, body: ""]
end

defmodule Warden.RedteamV2.Comment do
  @moduledoc false
  defstruct [:id, :workspace_id, :owner_id, body: ""]
end

defmodule Warden.RedteamV2.Thread do
  @moduledoc false
  # Has no field policy of its own; holds comments.
  defstruct [:id, comments: []]
end

defmodule Warden.RedteamV2.Authz do
  @moduledoc false
  # The authorizer of the v0.2 red-team suite. Every callback reports to
  # `context.test_pid`, so a test can see when user code was called and with what.
  use Warden.Authorizer,
    roles: [:admin, :staff],
    permissions: ["docs:read"],
    role_permissions: %{staff: ["docs:read"]},
    kinds: [:user, :agent, :webhook],
    tenant_roles: [:owner, :member],
    tenant_role_hierarchy: %{owner: [:member]},
    credential_scopes: ["docs:read"],
    policies: [Warden.RedteamV2.DocPolicy, Warden.RedteamV2.NotePolicy],
    fields: [Warden.RedteamV2.CommentFields],
    checks: [
      :owner,
      :context_owner,
      :reasoned,
      :dict,
      :racy,
      hooked: [system_kinds: [:webhook]],
      timed_dict: [timeout: 5_000],
      timed_racy: [timeout: 2],
      visible_many: [batch: true]
    ]

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
  def tenants(actor, _context), do: actor.subject |> Map.get(:memberships, %{}) |> Map.keys()

  @single_checks [
    :owner,
    :context_owner,
    :reasoned,
    :dict,
    :racy,
    :hooked,
    :timed_dict,
    :timed_racy
  ]

  @impl true
  def check(name, %Warden.Check{context: context} = check) when name in @single_checks do
    notify(context, {:check, name, tenant_of_value(check.value)})
    single(name, check)
  end

  defp single(:owner, %Warden.Check{actor: actor, value: value}), do: owner?(actor, value)

  # The 0.1-era shape: the user comes from the context, not from the actor.
  defp single(:context_owner, %Warden.Check{context: context, value: value}),
    do: is_map(value) and Map.get(value, :owner_id) == context[:current_user][:id]

  defp single(:reasoned, %Warden.Check{value: value}),
    do: {:deny, {:not_owner, %{body: Map.get(value || %{}, :body)}}}

  # A webhook may touch any doc it is handed; the check trusts the caller.
  defp single(:hooked, %Warden.Check{}), do: true

  defp single(name, %Warden.Check{}) when name in [:dict, :timed_dict],
    do: Process.get(:redteam_scope) == :tenant_a

  defp single(name, %Warden.Check{context: context}) when name in [:racy, :timed_racy] do
    Process.sleep(Map.get(context, :sleep, 0))
    true
  end

  @impl true
  def check_many(:visible_many, checks) do
    context = List.first(checks).context
    tenants = Enum.map(checks, &tenant_of_value(&1.value))
    notify(context, {:check_many, :visible_many, tenants})
    Enum.map(checks, &(is_map(&1.value) and Map.get(&1.value, :visible, false)))
  end

  defp owner?(%Warden.Actor{subject: %{id: id}}, %{owner_id: id}), do: true
  defp owner?(_actor, _value), do: false

  defp tenant_of_value(%{workspace_id: tenant}), do: tenant
  defp tenant_of_value(_value), do: nil

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.RedteamV2.DocPolicy do
  @moduledoc false
  # Read: public docs and the actor's own docs, inside `bounds[:doc_ids]` when the actor
  # has that bound. Ids from `arg:` are looked up in `context[:docs]`.
  use Warden.Policy,
    authorizer: Warden.RedteamV2.Authz,
    for: Warden.RedteamV2.Doc,
    actions: [:read, :write],
    tenant: :workspace_id,
    system_kinds: [:webhook]

  alias Warden.RedteamV2.Doc

  @impl true
  def allowed?(action, actor, value, context) do
    notify(context, {:allowed?, action, value})
    decide(action, actor, value, context)
  end

  defp decide(action, actor, {Doc, id}, context),
    do: decide(action, actor, Map.get(context[:docs] || %{}, id), context)

  defp decide(_action, _actor, nil, _context), do: false

  defp decide(action, actor, %Doc{} = doc, _context) do
    within_bounds?(actor, doc) and allowed_doc?(action, actor, doc)
  end

  defp allowed_doc?(:read, actor, doc), do: doc.public or owner?(actor, doc)
  defp allowed_doc?(:write, actor, doc), do: owner?(actor, doc)

  defp within_bounds?(actor, doc) do
    case Map.fetch(actor.bounds, :doc_ids) do
      {:ok, ids} -> doc.id in ids
      :error -> true
    end
  end

  defp owner?(%Warden.Actor{subject: %{id: id}}, %Doc{owner_id: id}), do: true
  defp owner?(_actor, _doc), do: false

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.RedteamV2.NotePolicy do
  @moduledoc false
  # Answers whatever the test puts in the context, to probe broken policies.
  use Warden.Policy,
    authorizer: Warden.RedteamV2.Authz,
    for: Warden.RedteamV2.Note,
    actions: [:read]

  @impl true
  def allowed?(:read, _actor, value, context), do: context.note_one.(value)

  @impl true
  def allowed_many(:read, _actor, values, context), do: context.note_many.(values)
end

defmodule Warden.RedteamV2.CommentFields do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.RedteamV2.Authz, for: Warden.RedteamV2.Comment

  redact :body, with: "[hidden]", unless: check(:owner)
end

defmodule Warden.RedteamV2.People do
  @moduledoc false
  # Abby owns tenant "a" and is a member of "b". Sam is a member of "a" only. Olivia is
  # an agent with memberships in "a" and "b".

  alias Warden.RedteamV2.Authz

  def abby, do: %{id: "abby", memberships: %{"a" => [:owner], "b" => [:member]}}
  def sam, do: %{id: "sam", memberships: %{"a" => [:member]}}

  def olivia,
    do: %{id: "olivia", kind: :agent, memberships: %{"a" => [:member], "b" => [:member]}}

  def staff, do: %{id: "staff", roles: [:staff], memberships: %{"a" => [:member]}}

  def context(user, extra \\ %{}), do: Map.merge(%{current_user: user, test_pid: self()}, extra)

  def actor(user, extra \\ %{}), do: Warden.actor(context(user, extra), authorizer: Authz)

  def bound_credential(tenant, extra \\ []),
    do:
      struct!(%Warden.Credential{method: :api_key, scopes: ["docs:read"], tenant: tenant}, extra)
end

defmodule Warden.RedteamV2.FarewellChannel do
  @moduledoc false
  # Rechecks on every push. Its terminate/2 pushes a farewell, and one event drops
  # Warden's socket state.
  use Phoenix.Channel
  import Warden.Rule

  use Warden.Phoenix.Channel,
    rule: role(:member),
    recheck: :every_push,
    authorizer: Warden.Test.ChannelAuthz

  @impl true
  def join(_topic, _params, socket), do: {:ok, socket}

  @impl true
  def handle_in("ping", _payload, socket), do: {:reply, :ok, socket}

  def handle_in("drop_state", _payload, socket) do
    stripped = %{socket | private: %{}}
    {:noreply, stripped}
  end

  @impl true
  def terminate(_reason, socket) do
    push(socket, "farewell", %{"secret" => "farewell-secret"})
    :ok
  end
end
