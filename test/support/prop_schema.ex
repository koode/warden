defmodule Warden.Test.Prop.Authz do
  @moduledoc false
  use Warden.Authorizer,
    roles: [:r1, :r2, :r3],
    permissions: ["p1", "p2"],
    role_hierarchy: %{r1: [:r2]},
    role_permissions: %{r2: ["p1"]},
    checks: [:owns]

  @impl true
  def subject(context), do: context[:actor]

  @impl true
  def roles(actor, _), do: actor.roles

  @impl true
  def permissions(actor, _), do: actor.perms

  @impl true
  def check(:owns, %Warden.Check{actor: actor, value: value}) do
    actor.subject != nil and is_map(value) and value[:owner] == actor.subject.id
  end
end

defmodule Warden.Test.Prop.Data do
  @moduledoc false

  @graph %{
    "a1" => %{
      kind: :alpha,
      owner: "u1",
      children: ["b1", "g1", "a2"],
      matrix: [["b1", "b2"], ["b2"]]
    },
    "a2" => %{kind: :alpha, owner: "u2", children: [], matrix: []},
    "b1" => %{kind: :beta, owner: "u1", parent: "a1"},
    "b2" => %{kind: :beta, owner: "u3", parent: "a2"},
    "g1" => %{kind: :gamma, owner: "u2", friends: ["a1", "a2"]}
  }

  @scalars %{
    alpha: [:name, :label, :secret_a],
    beta: [:name, :label, :secret_b],
    gamma: [:name, :label, :secret_g]
  }

  def ids, do: Map.keys(@graph) |> Enum.sort()
  def raw(id), do: Map.fetch!(@graph, id)
  def scalars(kind), do: Map.fetch!(@scalars, kind)

  # Every scalar value is a unique token "<id>.<field>".
  def entity(nil), do: nil

  def entity(id) do
    raw = raw(id)
    tokens = Map.new(scalars(raw.kind), fn f -> {f, "#{id}.#{f}"} end)
    raw |> Map.merge(tokens) |> Map.put(:id, id)
  end

  def all, do: Enum.map(ids(), &entity/1)
end

defmodule Warden.Test.Prop.Resolvers do
  @moduledoc false
  alias Warden.Test.Prop.Data

  def things(_, _, _), do: {:ok, Data.all()}
  def search(_, _, _), do: {:ok, Data.all()}
  def node(_, %{id: id}, _), do: {:ok, if(id in Data.ids(), do: Data.entity(id))}
  def alpha(_, %{id: id}, _), do: {:ok, if(id in Data.ids(), do: Data.entity(id))}
  def children(%{children: ids}, _, _), do: {:ok, Enum.map(ids, &Data.entity/1)}

  def matrix(%{matrix: rows}, _, _),
    do: {:ok, Enum.map(rows, fn row -> Enum.map(row, &Data.entity/1) end)}

  def parent(%{parent: id}, _, _), do: {:ok, Data.entity(id)}
  def friends(%{friends: ids}, _, _), do: {:ok, Enum.map(ids, &Data.entity/1)}
  def kind(%{kind: kind}, _), do: kind
end

defmodule Warden.Test.Prop.Schema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Schema, authorizer: Warden.Test.Prop.Authz

  alias Warden.Test.Prop.Resolvers, as: R

  interface :thing do
    field :id, :id
    field :name, :string

    field :label, :string do
      authorize role(:r3)
    end

    resolve_type &R.kind/2
  end

  object :alpha do
    interfaces [:thing]
    authorize role(:r2)

    field :id, :id
    field :name, :string
    field :label, :string

    field :secret_a, :string do
      authorize permission("p2")
    end

    field :children, list_of(:thing), resolve: &R.children/3
    field :matrix, list_of(list_of(:beta)), resolve: &R.matrix/3
  end

  object :beta do
    interfaces [:thing]
    authorize any_of([permission("p1"), check(:owns)])

    field :id, :id
    field :name, :string
    field :label, :string

    field :secret_b, :string do
      authorize role(:r1)
    end

    field :parent, :alpha, resolve: &R.parent/3
  end

  object :gamma do
    interfaces [:thing]

    field :id, :id
    field :name, :string
    field :label, :string

    field :secret_g, :string do
      authorize all_of([authenticated(), check(:owns)])
    end

    field :friends, list_of(:alpha), resolve: &R.friends/3
  end

  union :any_result do
    authorize authenticated()
    types [:alpha, :beta, :gamma]
    resolve_type &R.kind/2
  end

  input_object :thing_filter do
    field :kind, :string

    field :owner_only, :boolean, default_value: false do
      authorize authenticated()
    end
  end

  query do
    field :things, list_of(:thing) do
      arg :filter, :thing_filter
      resolve &R.things/3
    end

    field :search, list_of(:any_result), resolve: &R.search/3

    field :node, :thing do
      arg :id, non_null(:id)
      resolve &R.node/3
    end

    field :alpha, :alpha do
      arg :id, non_null(:id)
      arg :reveal, :boolean, default_value: false
      authorize_args reveal: role(:r3)
      resolve &R.alpha/3
    end
  end
end
