defmodule Warden.Test.RF.Probe do
  @moduledoc false
  # Resolvers and middleware report to the test process, to prove what ran.
  def hit(%{context: %{test_pid: pid}}, tag) when is_pid(pid), do: send(pid, {:rf_hit, tag})
  def hit(_, _), do: :ok
end

defmodule Warden.Test.RF.WriteMiddleware do
  @moduledoc false
  # Stands in for middleware that performs a write (audit log, counter, cache fill).
  @behaviour Absinthe.Middleware

  @impl true
  def call(res, tag) do
    Warden.Test.RF.Probe.hit(res, {:write, tag})
    res
  end
end

defmodule Warden.Test.RF.Authz do
  @moduledoc false
  use Warden.Authorizer,
    roles: [:admin, :member],
    permissions: ["read", "write"],
    role_hierarchy: %{admin: [:member]},
    role_permissions: %{admin: :all, member: ["read"]},
    checks: [:self, :tenant, :configured, :scoped_to_self]

  @impl true
  def subject(context), do: context[:user]

  @impl true
  def roles(%{roles: roles}, _context), do: roles
  def roles(_subject, _context), do: []

  @impl true
  def check(:self, %Warden.Check{actor: actor, value: value}) do
    is_map(value) and is_map(actor.subject) and
      Map.get(value, :owner_id) == Map.get(actor.subject, :id)
  end

  # A multi-tenant check that reads the request context, not the subject.
  def check(:tenant, %Warden.Check{context: context, value: value}) do
    is_map(value) and Map.get(value, :tenant) == context[:tenant]
  end

  # Returns whatever the test put in the context.
  def check(:configured, %Warden.Check{context: context}) do
    Map.get(context, :check_result, false)
  end

  # A scope check on an argument: "you may only ask for your own records".
  def check(:scoped_to_self, %Warden.Check{actor: actor, args: args}) do
    is_map(actor.subject) and Map.get(args, :owner_id) != nil and
      Map.get(args, :owner_id) == Map.get(actor.subject, :id)
  end

  @impl true
  def deny(denial) do
    case Process.get(:rf_deny_mode) do
      :null -> :null
      {:raw, value} -> value
      _ -> Warden.Authorizer.default_deny(denial, __warden_catalog__())
    end
  end
end

defmodule Warden.Test.RF.Data do
  @moduledoc false

  def accounts do
    [
      %{kind: :account, id: "a1", owner_id: "u1", email: "alice@secret.example"},
      %{kind: :account, id: "a2", owner_id: "u2", email: "bob@secret.example"}
    ]
  end

  def docs do
    [
      %{kind: :secret_doc, id: "s1", body: "TOPSECRET-s1"},
      %{kind: :public_doc, id: "p1", body: "public-p1"}
    ]
  end

  def doc(id), do: Enum.find(docs(), &(&1.id == id))
  def account(id), do: Enum.find(accounts(), &(&1.id == id))

  def tenant_doc(tenant),
    do: %{kind: :tenant_doc, id: "td-#{tenant}", tenant: tenant, body: "TENANT-SECRET-#{tenant}"}

  def user(id, roles), do: %{id: id, roles: roles}
end

defmodule Warden.Test.RF.Resolvers do
  @moduledoc false
  alias Warden.Test.RF.{Data, Probe}

  def kind(%{kind: kind}, _), do: kind

  def doc(_, %{id: id}, res) do
    Probe.hit(res, {:doc, id})
    {:ok, Data.doc(id)}
  end

  def docs(_, _, res) do
    Probe.hit(res, :docs)
    {:ok, Data.docs()}
  end

  def accounts(_, args, res) do
    Probe.hit(res, {:accounts, Map.get(args, :owner_id)})

    case Map.get(args, :owner_id) do
      nil -> {:ok, Data.accounts()}
      owner -> {:ok, Enum.filter(Data.accounts(), &(&1.owner_id == owner))}
    end
  end

  def account(_, %{id: id}, res) do
    Probe.hit(res, {:account, id})
    {:ok, Data.account(id)}
  end

  def by_status(_, %{status: status}, res) do
    Probe.hit(res, {:by_status, status})
    {:ok, ["listing for #{inspect(status)}"]}
  end

  def tagged(tag, value) do
    fn _, _, res ->
      Probe.hit(res, tag)
      {:ok, value}
    end
  end

  def root(payload, _, _), do: {:ok, payload}

  def string(tag) do
    fn _, _, res ->
      Probe.hit(res, tag)
      {:ok, "ran:#{inspect(tag)}"}
    end
  end
end

defmodule Warden.Test.RF.Schema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.RF.Authz

  alias Warden.Test.RF.{Probe, Resolvers}

  interface :node do
    field :id, non_null(:id)
    resolve_type &Resolvers.kind/2
  end

  # An interface with an explicitly public object rule: weaker than its implementors.
  interface :weak do
    authorize public()
    field :body, :string
    resolve_type &Resolvers.kind/2
  end

  object :secret_doc do
    interfaces [:node, :weak]
    authorize role(:admin)

    field :id, non_null(:id)
    field :body, :string
  end

  object :public_doc do
    interfaces [:node, :weak]

    field :id, non_null(:id)
    field :body, :string
  end

  union :search_result do
    authorize role(:member)
    types [:public_doc, :secret_doc]
    resolve_type &Resolvers.kind/2
  end

  object :account do
    authorize any_of([role(:admin), check(:self)])

    field :id, :id
    field :email, :string
  end

  object :tenant_doc do
    authorize check(:tenant)

    field :id, :id
    field :body, :string
  end

  enum :status do
    value :published
    value :draft
  end

  input_object :account_input do
    field :email, :string

    field :make_admin, :boolean, default_value: false do
      authorize role(:admin)
    end
  end

  query do
    field :node, :node do
      arg :id, non_null(:id)
      resolve &Resolvers.doc/3
    end

    field :nodes, list_of(:node), resolve: &Resolvers.docs/3

    field :weak, :weak do
      arg :id, non_null(:id)
      resolve &Resolvers.doc/3
    end

    field :weaks, list_of(:weak), resolve: &Resolvers.docs/3
    field :search, list_of(:search_result), resolve: &Resolvers.docs/3

    field :search_one, :search_result do
      arg :id, non_null(:id)
      resolve &Resolvers.doc/3
    end

    # Rajska #7: an optional scope argument guarded by an argument rule. The item type
    # carries the object rule that actually protects the data.
    field :accounts, list_of(:account) do
      arg :owner_id, :id
      authorize_args owner_id: check(:scoped_to_self)
      resolve &Resolvers.accounts/3
    end

    # Rajska #7, the scope expressed as a field rule that reads the arguments.
    field :scoped_accounts, list_of(:account) do
      arg :owner_id, :id
      authorize check(:scoped_to_self)
      resolve &Resolvers.accounts/3
    end

    # Rajska #7 with a non-null default: `null` must not slip past the rule.
    field :by_status, list_of(:string) do
      arg :status, :status, default_value: :published
      authorize_args status: role(:admin)
      resolve &Resolvers.by_status/3
    end

    field :account, :account do
      arg :id, non_null(:id)
      resolve &Resolvers.account/3
    end

    # Rajska #8: middleware declared before the resolver performs a write.
    field :guarded_write, :string do
      authorize role(:admin)
      middleware Warden.Test.RF.WriteMiddleware, :field
      resolve Resolvers.string(:guarded_write)
    end

    # Rajska #8: middleware/3 prepends a write middleware (escapable).
    field :mw3_write, :string do
      authorize role(:admin)
      resolve Resolvers.string(:mw3_write)
    end

    # Rajska #8: middleware/3 prepends a closure (Absinthe stores a runtime shim).
    field :mw3_closure, :string do
      authorize role(:admin)
      resolve Resolvers.string(:mw3_closure)
    end

    # Rajska #12.
    field :configured, :string do
      authorize check(:configured)
      resolve Resolvers.string(:configured)
    end

    field :whoami, :string do
      authorize authenticated()
      resolve Resolvers.string(:whoami)
    end

    field :admin_only, :string do
      authorize role(:admin)
      resolve Resolvers.string(:admin_only)
    end
  end

  mutation do
    authorize authenticated()

    field :delete_account, :boolean do
      arg :id, non_null(:id)
      authorize role(:admin)
      resolve Resolvers.tagged(:delete_account, true)
    end

    field :update_account, :account do
      arg :input, non_null(:account_input)
      resolve Resolvers.tagged(:update_account, hd(Warden.Test.RF.Data.accounts()))
    end

    field :archive_account, :boolean do
      arg :id, non_null(:id)
      arg :hard, :boolean, default_value: false
      authorize role(:member)
      authorize_args hard: role(:admin)
      resolve Resolvers.tagged(:archive_account, true)
    end

    # Protected only by the object rule of its return type.
    field :post_only_mutation, :account do
      arg :id, non_null(:id)
      resolve &__MODULE__.post_only/3
    end

    field :login, :string do
      arg :password, non_null(:string)
      authorize deny()
      resolve Resolvers.string(:login)
    end

    field :login_check, :string do
      arg :password, non_null(:string)
      authorize check(:configured)
      resolve Resolvers.string(:login_check)
    end
  end

  subscription do
    field :doc_changed, :secret_doc do
      config fn _, _ -> {:ok, topic: "rf_docs"} end
      resolve &Resolvers.root/3
    end

    field :admin_feed, :string do
      authorize role(:admin)
      config fn _, _ -> {:ok, topic: "rf_admin"} end

      resolve fn payload, _, res ->
        Probe.hit(res, :admin_feed)
        {:ok, payload}
      end
    end

    field :tenant_doc_changed, :tenant_doc do
      config fn _, _ -> {:ok, topic: "rf_tenant", context_id: "global"} end
      resolve &Resolvers.root/3
    end

    field :account_changed, :account do
      config fn _, _ -> {:ok, topic: "rf_accounts", context_id: "global"} end
      resolve &Resolvers.root/3
    end
  end

  def post_only(_, %{id: id}, res) do
    Probe.hit(res, :post_only_mutation)
    {:ok, Warden.Test.RF.Data.account(id)}
  end

  def middleware(middleware, %{identifier: :mw3_write}, %{identifier: :query}),
    do: [{Warden.Test.RF.WriteMiddleware, :mw3} | middleware]

  def middleware(middleware, %{identifier: :mw3_closure}, %{identifier: :query}) do
    [
      fn res, _ ->
        Probe.hit(res, {:write, :closure})
        res
      end
      | middleware
    ]
  end

  def middleware(middleware, _field, _object), do: middleware
end

defmodule Warden.Test.RF.PersistentSchema do
  @moduledoc false
  # The same kind of rules on a schema compiled with the PersistentTerm provider, whose
  # schema pipeline differs (InlineFunctions with inline_always, PopulatePersistentTerm).
  use Absinthe.Schema
  @schema_provider Absinthe.Schema.PersistentTerm
  use Warden.Absinthe, authorizer: Warden.Test.RF.Authz

  object :secret_doc do
    authorize role(:admin)
    field :id, non_null(:id)
    field :body, :string
  end

  query do
    field :doc, :secret_doc do
      resolve fn _, _, _ -> {:ok, Warden.Test.RF.Data.doc("s1")} end
    end

    field :guarded_write, :string do
      authorize role(:admin)

      resolve fn _, _, res ->
        Warden.Test.RF.Probe.hit(res, :guarded_write)
        {:ok, "ran"}
      end
    end
  end

  def middleware(middleware, %{identifier: :guarded_write}, %{identifier: :query}) do
    [
      fn res, _ ->
        Warden.Test.RF.Probe.hit(res, {:write, :persistent_closure})
        res
      end
      | middleware
    ]
  end

  def middleware(middleware, _field, _object), do: middleware
end
