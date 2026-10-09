defmodule Warden.Redteam.Data do
  @moduledoc false

  def users do
    [
      %{kind: :user, id: "u1", name: "Alice", email: "alice@example.com", author_id: nil},
      %{kind: :user, id: "u2", name: "Bob", email: "bob@example.com", author_id: nil},
      %{kind: :user, id: "u3", name: "Carol", email: "carol@example.com", author_id: nil}
    ]
  end

  def posts do
    [
      %{kind: :post, id: "p1", title: "Hello", author_id: "u2", draft_notes: "NOTES-P1"},
      %{kind: :post, id: "p2", title: "World", author_id: "u3", draft_notes: "NOTES-P2"}
    ]
  end

  def secrets do
    [
      %{kind: :secret, id: "s1", code: "ALPHA"},
      %{kind: :secret, id: "s2", code: "BRAVO"}
    ]
  end

  def things do
    [
      %{kind: :public_thing, id: "t1", label: "T1"},
      %{kind: :public_thing, id: "t2", label: "T2"}
    ]
  end

  def all, do: users() ++ posts() ++ secrets() ++ things()

  def get(id), do: Enum.find(all(), &(&1.id == id))

  # Every entity carries a secret note.
  def with_note(nil), do: nil
  def with_note(item), do: Map.put(item, :secret_note, "NOTE-" <> item.id)

  def probe(res, tag) do
    case res do
      %{context: %{test_pid: pid}} when is_pid(pid) -> send(pid, {:resolved, tag})
      _ -> :ok
    end
  end
end

defmodule Warden.Redteam.Types do
  @moduledoc false
  # Abstract types, objects and input objects shared by the red-team schemas.
  use Absinthe.Schema.Notation
  use Warden.Absinthe.Notation

  alias Warden.Redteam.Data

  interface :node do
    field :id, non_null(:id)
    resolve_type fn %{kind: kind}, _ -> kind end
  end

  interface :entity do
    authorize authenticated()

    field :id, non_null(:id)

    field :secret_note, :string do
      authorize role(:admin)
    end

    field :owner, :entity

    resolve_type fn %{kind: kind}, _ -> kind end
  end

  interface :auditable do
    field :secret_note, :string do
      authorize role(:auditor)
    end

    resolve_type fn %{kind: kind}, _ -> kind end
  end

  # An interface that implements another interface and re-declares its fields without
  # rules.
  interface :named_entity do
    interfaces [:entity]
    field :id, non_null(:id)
    field :secret_note, :string
    field :owner, :entity
    field :label, :string
    resolve_type fn %{kind: kind}, _ -> kind end
  end

  interface :searchable do
    field :items, list_of(:public_thing) do
      arg :include_hidden, :boolean, default_value: false
      authorize_args include_hidden: role(:admin)
      list_policy :filter
    end

    field :secrets, list_of(:secret) do
      list_policy :filter
    end

    resolve_type fn _, _ -> :folder end
  end

  object :user do
    interfaces [:node, :entity, :named_entity]
    authorize any_of([role(:admin), check(:self)])

    field :id, non_null(:id)
    field :name, :string
    field :label, :string, resolve: fn u, _, _ -> {:ok, u.name} end

    field :email, :string do
      authorize role(:admin)
    end

    field :secret_note, :string

    field :owner, :entity do
      resolve fn _, _, _ -> {:ok, Data.with_note(Data.get("s1"))} end
    end

    field :friends, list_of(:user) do
      resolve fn _, _, _ -> {:ok, Data.users()} end
    end
  end

  object :post do
    interfaces [:node, :entity, :auditable]

    field :id, non_null(:id)
    field :title, :string
    field :secret_note, :string

    field :draft_notes, :string do
      authorize role(:editor)
    end

    field :owner, :entity do
      resolve fn p, _, _ -> {:ok, Data.with_note(Data.get(p.author_id))} end
    end

    field :author, :user do
      resolve fn p, _, _ -> {:ok, Data.get(p.author_id)} end
    end
  end

  object :secret do
    interfaces [:node]
    authorize role(:admin)

    field :id, non_null(:id)
    field :code, :string
  end

  object :public_thing do
    interfaces [:node]
    field :id, non_null(:id)
    field :label, :string
  end

  object :folder do
    interfaces [:searchable]

    field :items, list_of(:public_thing) do
      arg :include_hidden, :boolean, default_value: false

      resolve fn _, args, res ->
        Data.probe(res, {:folder_items, args.include_hidden})
        {:ok, Data.things()}
      end
    end

    field :secrets, list_of(:secret) do
      resolve fn _, _, _ -> {:ok, Data.secrets() ++ Data.things()} end
    end
  end

  object :wrapper do
    field :label, :string, resolve: fn _, _, _ -> {:ok, "W"} end

    field :items, non_null(list_of(non_null(:secret))) do
      resolve fn _, _, _ -> {:ok, Data.secrets()} end
    end
  end

  union :search_result do
    types [:user, :post, :secret, :public_thing]
    resolve_type fn %{kind: kind}, _ -> kind end
  end

  union :admin_result do
    authorize role(:admin)
    types [:public_thing, :post]
    resolve_type fn %{kind: kind}, _ -> kind end
  end

  # A union whose members are resolved through is_type_of, not resolve_type.
  union :typed_result do
    types [:typed_secret, :typed_public]
  end

  object :typed_secret do
    authorize role(:admin)
    is_type_of fn v -> v[:kind] == :secret end
    field :code, :string
  end

  object :typed_public do
    is_type_of fn v -> v[:kind] == :public_thing end
    field :label, :string
  end

  # resolve_type returns a type that is not a member of the union.
  union :odd_result do
    types [:public_thing]
    resolve_type fn _, _ -> :secret end
  end

  # resolve_type returns a type that does not implement the interface.
  interface :odd_iface do
    field :id, non_null(:id)
    resolve_type fn _, _ -> :secret end
  end

  object :odd_impl do
    interfaces [:odd_iface]
    field :id, non_null(:id)
  end

  enum :post_status do
    value :published
    value :draft
    value :archived
  end

  input_object :inner_filter do
    field :deep_flag, :boolean do
      authorize role(:admin)
    end

    field :status, :post_status, default_value: :published do
      authorize role(:admin)
    end
  end

  input_object :post_filter do
    field :title, :string

    field :reveal_deleted, :boolean, default_value: false do
      authorize role(:admin)
    end

    field :nested, :inner_filter
    field :children, list_of(:inner_filter)
    field :grid, list_of(list_of(:inner_filter))
  end
end

defmodule Warden.Redteam.ShapeSchema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Redteam.Authz

  alias Warden.Redteam.Data

  import_types Warden.Redteam.Types

  query do
    field :node, :node do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _ -> {:ok, Data.with_note(Data.get(id))} end
    end

    field :nodes, list_of(:node) do
      arg :ids, list_of(non_null(:id))
      resolve fn %{ids: ids}, _ -> {:ok, Enum.map(ids, &Data.with_note(Data.get(&1)))} end
    end

    field :entity, :entity do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _ -> {:ok, Data.with_note(Data.get(id))} end
    end

    field :named, :named_entity do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _ -> {:ok, Data.with_note(Data.get(id))} end
    end

    field :auditable, :auditable do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _ -> {:ok, Data.with_note(Data.get(id))} end
    end

    field :post, :post do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _ -> {:ok, Data.with_note(Data.get(id))} end
    end

    field :search, list_of(:search_result) do
      arg :ids, list_of(non_null(:id))
      resolve fn %{ids: ids}, _ -> {:ok, Enum.map(ids, &Data.get/1)} end
    end

    field :search_filter, list_of(:search_result) do
      list_policy :filter
      arg :ids, list_of(non_null(:id))
      resolve fn %{ids: ids}, _ -> {:ok, Enum.map(ids, &Data.get/1)} end
    end

    field :search_fail, list_of(:search_result) do
      list_policy :fail_list
      arg :ids, list_of(non_null(:id))
      resolve fn %{ids: ids}, _ -> {:ok, Enum.map(ids, &Data.get/1)} end
    end

    field :secrets_nn, non_null(list_of(non_null(:secret))) do
      resolve fn _, _ -> {:ok, Data.secrets()} end
    end

    field :secrets_nested, list_of(list_of(non_null(:secret))) do
      resolve fn _, _ -> {:ok, [Data.things(), Data.secrets()]} end
    end

    field :grid, non_null(list_of(non_null(list_of(:node)))) do
      resolve fn _, _ -> {:ok, [Data.things(), [hd(Data.things()) | Data.secrets()]]} end
    end

    field :grid_filter, list_of(list_of(:node)) do
      list_policy :filter
      resolve fn _, _ -> {:ok, [Data.secrets(), [hd(Data.secrets()) | Data.things()]]} end
    end

    field :grid_fail, list_of(list_of(:node)) do
      list_policy :fail_list
      resolve fn _, _ -> {:ok, [Data.things(), [hd(Data.things()), hd(Data.secrets())]]} end
    end

    field :wrapper, :wrapper do
      resolve fn _, _ -> {:ok, %{}} end
    end

    field :admin_result, :admin_result do
      resolve fn _, _ -> {:ok, hd(Data.things())} end
    end

    field :admin_results, list_of(:admin_result) do
      list_policy :filter
      resolve fn _, _ -> {:ok, Data.things() ++ Data.posts()} end
    end

    field :typed, list_of(:typed_result) do
      resolve fn _, _ -> {:ok, Data.secrets() ++ Data.things()} end
    end

    field :odd, :odd_result do
      resolve fn _, _ -> {:ok, hd(Data.secrets())} end
    end

    field :odd_iface, :odd_iface do
      resolve fn _, _ -> {:ok, hd(Data.secrets())} end
    end

    field :folder, :folder do
      resolve fn _, _ -> {:ok, %{}} end
    end

    field :searchable, :searchable do
      resolve fn _, _ -> {:ok, %{}} end
    end

    field :posts, list_of(:post) do
      arg :status, :post_status, default_value: :published
      arg :include_drafts, :boolean, default_value: false
      arg :filter, :post_filter
      arg :filters, list_of(:post_filter)
      authorize_args status: role(:admin), include_drafts: role(:editor)

      resolve fn _, res ->
        Data.probe(res, :posts)
        {:ok, Data.posts()}
      end
    end

    # Field names that collide with root and introspection names.
    field :query, :string do
      authorize role(:admin)
      resolve fn _, _ -> {:ok, "Q-SECRET"} end
    end

    field :mutation, :string do
      authorize role(:admin)
      resolve fn _, _ -> {:ok, "M-SECRET"} end
    end

    field :subscription, :string do
      authorize role(:admin)
      resolve fn _, _ -> {:ok, "S-SECRET"} end
    end

    field :schema, :string do
      authorize role(:admin)
      resolve fn _, _ -> {:ok, "SCHEMA-SECRET"} end
    end

    # A query field that returns the mutation root type.
    field :mutations, :mutation do
      resolve fn _, _ -> {:ok, %{}} end
    end
  end

  mutation do
    field :delete_user, :boolean do
      authorize role(:admin)
      arg :id, :id

      resolve fn _, res ->
        Data.probe(res, :delete_user)
        {:ok, true}
      end
    end

    field :update_post, :boolean do
      arg :input, :post_filter
      arg :inputs, list_of(non_null(:post_filter))

      resolve fn _, res ->
        Data.probe(res, :update_post)
        {:ok, true}
      end
    end
  end
end
