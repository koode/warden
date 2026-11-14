defmodule Warden.Test.RedteamV2.Card do
  @moduledoc false
  # A card is read through the `Cards` policy and redacted by `CardFields`.
  defstruct [:id, :workspace_id, kind: "plain", visible: true, note: "card note", code: "c0de"]

  def all do
    [
      %__MODULE__{id: 1, workspace_id: "t1", note: "note 1", visible: true},
      %__MODULE__{id: 2, workspace_id: "t1", note: "note 2", visible: false},
      %__MODULE__{id: 3, workspace_id: "t2", note: "note 3", visible: true}
    ]
  end

  def get(id), do: Enum.find(all(), &(&1.id == id))
end

defmodule Warden.Test.RedteamV2.Ticket do
  @moduledoc false
  # A ticket is guarded by the batched check `live` (its `visible` flag).
  defstruct [:id, :workspace_id, visible: true, secret: "ticket secret", blob: ""]
end

defmodule Warden.Test.RedteamV2.Listing do
  @moduledoc false
  # `kind` decides the GraphQL type of a listing ("secret" or anything else).
  defstruct [:id, kind: "plain", code: "listing code"]
end

defmodule Warden.Test.RedteamV2.Authz do
  @moduledoc false
  # The authorizer of the 0.2 Absinthe red-team suite. Calls are reported to
  # `context.test_pid`.
  use Warden.Authorizer,
    roles: [:staff],
    tenant_roles: [:owner, :member],
    tenant_role_hierarchy: %{owner: [:member]},
    policies: [Warden.Test.RedteamV2.Cards],
    fields: [Warden.Test.RedteamV2.CardFields, Warden.Test.RedteamV2.ListingFields],
    checks: [
      :reasoned,
      live: [batch: true],
      slow_live: [batch: true, timeout: 6_000]
    ]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def tenant_roles(user, tenant, context) do
    notify(context, {:tenant_roles, user.id, tenant})
    user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
  end

  @impl true
  def check(:reasoned, %Warden.Check{context: context}),
    do: Map.get(context, :reasoned, {:deny, {:quota, %{secret: "s3cr3t-detail"}}})

  @impl true
  def check_many(:live, checks) do
    notify(List.first(checks).context, {:check_many, :live, length(checks)})
    Enum.map(checks, &(is_map(&1.value) and Map.get(&1.value, :visible, false)))
  end

  def check_many(:slow_live, checks) do
    context = List.first(checks).context
    Process.sleep(Map.get(context, :sleep, 0))
    Enum.map(checks, fn _check -> true end)
  end

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.Test.RedteamV2.ExposingAuthz do
  @moduledoc false
  # Opts in to denial reasons in the default error.
  use Warden.Authorizer,
    roles: [:staff],
    expose_denial_reasons: true,
    checks: [:reasoned, :other_reasoned]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def check(:reasoned, %Warden.Check{}),
    do: {:deny, {:quota, %{secret: "s3cr3t-detail", subject_email: "abby@example.com"}}}

  def check(:other_reasoned, %Warden.Check{}), do: {:deny, :not_member}
end

defmodule Warden.Test.RedteamV2.Cards do
  @moduledoc false
  # Read: visible cards. A card without an id is a new card, which this policy allows
  # (a plausible rule for a create action); Warden must never ask about it for `arg:`.
  use Warden.Policy,
    authorizer: Warden.Test.RedteamV2.Authz,
    for: Warden.Test.RedteamV2.Card,
    actions: [:read],
    tenant: :workspace_id

  alias Warden.Test.RedteamV2.Card

  @impl true
  def allowed?(:read, _actor, value, context), do: decide(value, context)

  @impl true
  def allowed_many(:read, _actor, values, context) do
    notify(context, {:allowed_many, length(values)})
    Enum.each(values, &notify(context, {:asked_about, &1}))

    case context[:policy_many] do
      nil -> Enum.map(values, &decide(&1, context))
      fun -> fun.(values)
    end
  end

  defp decide({Card, nil}, _context), do: true
  defp decide({Card, id}, context), do: decide(Card.get(id), context)
  defp decide(%Card{visible: visible}, _context), do: visible
  defp decide(_other, _context), do: false

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.Test.RedteamV2.CardFields do
  @moduledoc false
  use Warden.Fields, authorizer: Warden.Test.RedteamV2.Authz, for: Warden.Test.RedteamV2.Card

  redact :note, with: "[hidden]", unless: role(:staff)
end

defmodule Warden.Test.RedteamV2.ListingFields do
  @moduledoc false
  # Non-staff actors see every listing as "plain".
  use Warden.Fields, authorizer: Warden.Test.RedteamV2.Authz, for: Warden.Test.RedteamV2.Listing

  redact :kind, with: "plain", unless: role(:staff)
end

defmodule Warden.Test.RedteamV2.People do
  @moduledoc false
  # Abby is a member of "t1" only; staff has the instance role.

  def abby, do: %{id: "abby", memberships: %{"t1" => [:member]}}
  def staff, do: %{id: "staff", roles: [:staff]}

  def context(user, extra \\ %{}), do: Map.merge(%{current_user: user, test_pid: self()}, extra)

  def run(schema, document, user, extra \\ %{}, variables \\ %{}) do
    case Absinthe.run(document, schema, context: context(user, extra), variables: variables) do
      {:ok, result} -> result
      other -> raise "unexpected result: #{inspect(other)}"
    end
  end
end

defmodule Warden.Test.RedteamV2.Schema do
  @moduledoc false
  # The schema the 0.2 Absinthe red-team attacks: a policy object rule with redaction,
  # a batched check object rule behind an interface, a discriminated interface whose
  # discriminator is redacted, a second type over a redacted struct, `can/3` with `arg:`
  # and `on_deny: {:replace, value}`.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.RedteamV2.Authz

  alias Warden.Test.RedteamV2.{Card, CardFields, Cards, Listing, ListingFields, Ticket}

  interface :entry do
    field :id, non_null(:integer)

    resolve_type fn
      %Card{}, _resolution -> :card
      %Ticket{}, _resolution -> :ticket
      _other, _resolution -> nil
    end
  end

  interface :listing do
    field :id, non_null(:integer)

    resolve_type fn
      %Listing{kind: "secret"}, _resolution -> :secret_listing
      %Listing{}, _resolution -> :plain_listing
      _other, _resolution -> nil
    end
  end

  object :card do
    interface :entry
    authorize can(Cards, :read)
    redact_with CardFields

    field :id, non_null(:integer)
    field :note, :string
    field :code, :string
  end

  # A second type over the redacted struct must redact too (a compile-time rule).
  object :card_summary do
    authorize can(Cards, :read)
    redact_with CardFields

    field :id, non_null(:integer)
    field :note, :string
  end

  object :ticket do
    interface :entry
    authorize check(:live)

    field :id, non_null(:integer)
    field :secret, :string
    field :workspace_id, :string
  end

  object :guarded_ticket do
    authorize authenticated()

    field :id, :integer
    field :secret, :string
  end

  object :secret_listing do
    interface :listing
    authorize authenticated()
    redact_with ListingFields

    field :id, non_null(:integer)
    field :kind, :string

    field :code, :string do
      authorize role(:staff)
    end
  end

  object :plain_listing do
    interface :listing
    redact_with ListingFields

    field :id, non_null(:integer)
    field :kind, :string
    field :code, :string
  end

  query do
    field :cards, list_of(:card) do
      resolve fn _args, resolution -> {:ok, Map.get(resolution.context, :cards, Card.all())} end
    end

    field :card_summaries, list_of(:card_summary) do
      resolve fn _args, resolution -> {:ok, Map.get(resolution.context, :cards, Card.all())} end
    end

    field :entries, list_of(:entry) do
      resolve fn _args, resolution -> {:ok, resolution.context.entries} end
    end

    field :tickets, list_of(:ticket) do
      resolve fn _args, resolution -> {:ok, resolution.context.entries} end
    end

    field :guarded_ticket, :guarded_ticket do
      resolve fn _args, resolution -> {:ok, resolution.context.ticket} end
    end

    field :listings, list_of(:listing) do
      resolve fn _args, resolution -> {:ok, resolution.context.listings} end
    end

    field :cards_by_ids, list_of(:card) do
      arg :ids, list_of(:integer)
      authorize can(Cards, :read, arg: [:ids])

      resolve fn args, resolution ->
        send(resolution.context.test_pid, {:resolver_ran, :cards_by_ids, args})
        {:ok, Enum.map(Map.get(args, :ids) || [], &Card.get/1)}
      end
    end

    field :featured_card, :card do
      authorize(role(:staff), on_deny: {:replace, %Card{id: 9, note: "replacement note"}})

      resolve fn _args, resolution ->
        send(resolution.context.test_pid, {:resolver_ran, :featured_card})
        {:ok, Card.get(1)}
      end
    end
  end
end

defmodule Warden.Test.RedteamV2.AcrossSchema do
  @moduledoc false
  # Cross-parent batching: one card, one ticket and one slow ticket per holder.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.RedteamV2.Authz, batch_across_parents: true

  alias Warden.Test.RedteamV2.{CardFields, Cards}

  object :card do
    authorize can(Cards, :read)
    redact_with CardFields

    field :id, non_null(:integer)
    field :note, :string
  end

  object :ticket do
    authorize check(:live)

    field :id, non_null(:integer)
    field :secret, :string
  end

  object :slow_ticket do
    authorize check(:slow_live)

    field :id, non_null(:integer)
  end

  object :holder do
    field :id, non_null(:integer)
    field :card, :card
    field :ticket, :ticket

    field :required_ticket, non_null(:ticket),
      resolve: fn holder, _args, _res -> {:ok, holder.ticket} end

    field :slow_ticket, :slow_ticket, resolve: fn holder, _args, _res -> {:ok, holder.ticket} end
  end

  query do
    field :holders, list_of(:holder) do
      resolve fn _args, resolution -> {:ok, resolution.context.holders} end
    end
  end
end
