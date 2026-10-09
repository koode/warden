defmodule Warden.Test.FZ.Authz do
  @moduledoc false
  # Authorizer for the red-team fuzz schema. The denial handler mode is read from the
  # process dictionary (`:fz_deny_mode`), so one compiled schema covers every handler
  # return: the default handler, `:null`, `{:replace, value}` and an "always error"
  # handler that also errors for filtered list items.
  use Warden.Authorizer,
    roles: [:a, :b, :c],
    permissions: ["p1", "p2", "p3"],
    role_hierarchy: %{a: [:b]},
    role_permissions: %{a: :all, b: ["p1"]},
    checks: [:owns]

  alias Warden.Test.FZ.Data

  @impl true
  def subject(context), do: context[:actor]

  @impl true
  def roles(actor, _context), do: actor.roles

  @impl true
  def permissions(actor, _context), do: actor.perms

  @impl true
  def check(:owns, %Warden.Check{actor: actor, value: value}) do
    actor.subject != nil and is_map(value) and Map.get(value, :owner) == actor.subject.id
  end

  # Opt in to subscription sharing (decision 8: off by default). Every rule here reads
  # only the subject id, roles and permissions, so the default key is sound and the
  # fuzz keeps exercising shared resolutions.
  @impl true
  def actor_key(actor, _context), do: Warden.Authorizer.default_actor_key(actor)

  @impl true
  def deny(%Warden.Denial{} = denial) do
    case Process.get(:fz_deny_mode, :error) do
      :error ->
        Warden.Authorizer.default_deny(denial, __warden_catalog__())

      :null ->
        :null

      :strict_error ->
        {:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}

      :replace ->
        if denial.kind == :field,
          do: {:replace, Data.replacement(denial.field)},
          else: Warden.Authorizer.default_deny(denial, __warden_catalog__())
    end
  end
end

defmodule Warden.Test.FZ.Data do
  @moduledoc false

  @graph %{
    "d1" => %{
      kind: :doc,
      owner: "u1",
      files: ["f1", "f2"],
      related: ["n1", "d2", "f1"],
      hits: [["d2", "f1"], ["n1"]]
    },
    "d2" => %{kind: :doc, owner: "u2", files: ["f2"], related: [], hits: [[]]},
    "f1" => %{kind: :file, owner: "u1", parent: "d1", siblings: ["f2"]},
    "f2" => %{kind: :file, owner: "u3", parent: "d2", siblings: ["f1", "f2"]},
    "n1" => %{kind: :note, owner: "u2", docs: ["d1", "d2"]},
    "n2" => %{kind: :note, owner: "u1", docs: []},
    # The decoy a `{:replace, value}` handler substitutes for denied object fields.
    "dx" => %{kind: :doc, owner: "u3", files: [], related: ["n2"], hits: []}
  }

  @scalars %{
    doc: [:title, :label, :owner_name, :secret_doc],
    file: [:title, :label, :owner_name, :blob],
    note: [:title, :label, :text]
  }

  def graph_ids, do: Map.keys(@graph) |> Enum.sort()
  def ids, do: graph_ids() -- ["dx"]
  def ids_of(kind), do: Enum.filter(ids(), &(raw(&1).kind == kind))
  def raw(id), do: Map.fetch!(@graph, id)
  def scalars(kind), do: Map.fetch!(@scalars, kind)

  # Every scalar is a unique token "<id>.<field>".
  def entity(nil), do: nil

  def entity(id) do
    raw = raw(id)
    tokens = Map.new(scalars(raw.kind), fn f -> {f, "#{id}.#{f}"} end)
    raw |> Map.merge(tokens) |> Map.put(:id, id)
  end

  def lookup(id), do: if(Map.has_key?(@graph, id), do: entity(id))

  def all, do: Enum.map(ids(), &entity/1)

  def matrix, do: [[entity("d1"), entity("f1")], [entity("n1"), entity("f2")]]

  def replacement(field) when field in [:vault, :purge], do: entity("dx")
  def replacement(:touch), do: nil
  def replacement(_scalar), do: "R"
end

defmodule Warden.Test.FZ.Resolvers do
  @moduledoc false
  alias Absinthe.Resolution.Helpers
  alias Warden.Test.FZ.Data

  def kind(%{kind: kind}, _), do: kind

  def all(_, _, _), do: {:ok, Data.all()}

  def owned(_, _, _),
    do: {:ok, Enum.filter(Data.all(), &(&1.kind in [:doc, :file]))}

  def notes(_, _, _), do: {:ok, Enum.filter(Data.all(), &(&1.kind == :note))}
  def matrix(_, _, _), do: {:ok, Data.matrix()}
  def node(_, %{id: id}, _), do: {:ok, if(id in Data.ids(), do: Data.entity(id))}

  def doc(_, %{id: id}, _) do
    {:ok, if(id in Data.ids_of(:doc), do: Data.entity(id))}
  end

  def vault(_, _, _), do: {:ok, Data.entity("d2")}

  def children(key) do
    fn parent, _args, _res ->
      {:ok, parent |> Map.fetch!(key) |> Enum.map(&Data.entity/1)}
    end
  end

  def files(p, a, r), do: children(:files).(p, a, r)

  # Suspended resolution: Warden's post check must see the value after `Async`.
  def related(p, a, r) do
    Helpers.async(fn -> children(:related).(p, a, r) end)
  end

  def siblings(p, a, r) do
    Helpers.async(fn -> children(:siblings).(p, a, r) end)
  end

  # Suspended resolution through `Batch`.
  def docs(%{id: id}, _a, _r) do
    Helpers.batch({__MODULE__, :load_docs}, id, fn results ->
      {:ok, Map.fetch!(results, id)}
    end)
  end

  def load_docs(_, note_ids) do
    Map.new(note_ids, fn id -> {id, Enum.map(Data.raw(id).docs, &Data.entity/1)} end)
  end

  def hits(%{hits: rows}, _, _),
    do: {:ok, Enum.map(rows, fn row -> Enum.map(row, &Data.entity/1) end)}

  def parent(%{parent: id}, _, _), do: {:ok, Data.entity(id)}

  # Side-effect probe: every mutation resolver reports to the test process.
  defp effect(%{context: %{test_pid: pid}}, tag, args) when is_pid(pid),
    do: send(pid, {:fz_side_effect, tag, args})

  defp effect(_, _, _), do: :ok

  def touch(_, %{id: id} = args, res) do
    effect(res, :touch, args)
    {:ok, Data.lookup(id)}
  end

  def purge(_, %{id: id} = args, res) do
    effect(res, :purge, args)
    {:ok, if(id in Data.ids_of(:doc), do: Data.entity(id))}
  end

  def annotate(_, %{input: %{id: id}} = args, res) do
    effect(res, :annotate, args)
    {:ok, if(id in Data.ids_of(:note), do: Data.entity(id))}
  end

  def rotate(_, %{id: id} = args, res) do
    effect(res, :rotate, args)
    {:ok, if(id in Data.ids_of(:file), do: Data.entity(id))}
  end

  def root(payload, _, _), do: {:ok, payload}
end

defmodule Warden.Test.FZ.Schema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.FZ.Authz

  alias Warden.Test.FZ.Resolvers, as: R

  interface :item do
    field :id, :id
    field :title, :string

    field :label, :string do
      authorize role(:c)
    end

    resolve_type &R.kind/2
  end

  interface :owned do
    authorize any_role([:a, :b, :c])

    field :id, :id

    field :owner_name, :string do
      authorize authenticated()
    end

    resolve_type &R.kind/2
  end

  object :doc do
    interfaces [:item, :owned]
    authorize any_of([role(:b), check(:owns)])

    field :id, :id
    field :title, :string

    field :label, :string do
      authorize authenticated()
    end

    field :owner_name, :string

    field :secret_doc, :string do
      authorize permission("p2")
    end

    field :files, list_of(non_null(:file)) do
      list_policy :filter
      resolve &R.files/3
    end

    field :related, list_of(:item) do
      arg :kind, :string
      authorize_args kind: permission("p3")
      resolve &R.related/3
    end

    field :hits, list_of(list_of(:hit)) do
      list_policy :fail_list
      resolve &R.hits/3
    end
  end

  object :file do
    interfaces [:item, :owned]
    authorize permission("p1")

    field :id, :id
    field :title, :string
    field :label, :string
    field :owner_name, :string

    field :blob, :string do
      authorize role(:a)
    end

    field :parent, :doc, resolve: &R.parent/3

    field :siblings, non_null(list_of(:file)) do
      list_policy :fail_list
      resolve &R.siblings/3
    end
  end

  object :note do
    interfaces [:item]

    field :id, :id
    field :title, :string

    field :label, :string do
      authorize permission("p3")
    end

    field :text, non_null(:string) do
      authorize check(:owns)
    end

    field :docs, list_of(non_null(:doc)), resolve: &R.docs/3
  end

  union :hit do
    authorize authenticated()
    types [:doc, :file, :note]
    resolve_type &R.kind/2
  end

  enum :status do
    value :published
    value :draft
  end

  input_object :item_filter do
    field :kind, :string

    field :include_hidden, :boolean, default_value: false do
      authorize role(:a)
    end

    field :owner, :string do
      authorize authenticated()
    end

    field :and, list_of(:item_filter)
  end

  input_object :tag_input do
    field :name, non_null(:string)

    field :secret, :boolean, default_value: false do
      authorize permission("p2")
    end
  end

  input_object :annotate_input do
    field :id, non_null(:id)
    field :text, :string

    field :pin, :boolean, default_value: false do
      authorize role(:c)
    end

    field :tags, list_of(non_null(:tag_input))
  end

  query do
    field :items, list_of(:item) do
      arg :filter, :item_filter
      arg :limit, :integer, default_value: 10
      authorize_args limit: role(:b)
      resolve &R.all/3
    end

    field :items_filtered, list_of(non_null(:item)) do
      list_policy :filter
      resolve &R.all/3
    end

    field :items_strict, list_of(:item) do
      list_policy :fail_list
      resolve &R.all/3
    end

    field :owned, list_of(:owned), resolve: &R.owned/3

    field :hits, list_of(:hit) do
      list_policy :filter
      resolve &R.all/3
    end

    field :hits_nn, list_of(non_null(:hit)), resolve: &R.all/3

    field :node, :item do
      arg :id, non_null(:id)
      resolve &R.node/3
    end

    field :doc, :doc do
      arg :id, non_null(:id)
      arg :reveal, :boolean, default_value: false
      authorize_args reveal: role(:c)
      resolve &R.doc/3
    end

    field :vault, :doc do
      authorize role(:a)
      resolve &R.vault/3
    end

    field :status_items, list_of(:note) do
      arg :status, :status, default_value: :published
      authorize_args status: role(:a)
      resolve &R.notes/3
    end

    field :matrix, list_of(list_of(non_null(:hit))), resolve: &R.matrix/3
  end

  mutation do
    authorize any_role([:a, :b, :c])

    field :touch, :item do
      arg :id, non_null(:id)
      authorize authenticated()
      resolve &R.touch/3
    end

    field :purge, :doc do
      arg :id, non_null(:id)
      arg :force, :boolean, default_value: false
      authorize role(:b)
      authorize_args force: role(:a)
      resolve &R.purge/3
    end

    field :annotate, :note do
      arg :input, non_null(:annotate_input)
      resolve &R.annotate/3
    end

    field :rotate, :file do
      arg :id, non_null(:id)
      resolve &R.rotate/3
    end
  end

  subscription do
    field :item_updated, :item do
      arg :channel, non_null(:string)
      config fn args, _ -> {:ok, topic: args.channel, context_id: "global"} end
      resolve &R.root/3
    end

    field :doc_updated, :doc do
      arg :channel, non_null(:string)
      arg :reveal, :boolean, default_value: false
      authorize authenticated()
      authorize_args reveal: role(:c)
      config fn args, _ -> {:ok, topic: args.channel, context_id: "global"} end
      resolve &R.root/3
    end

    field :hit_updated, :hit do
      arg :channel, non_null(:string)
      config fn args, _ -> {:ok, topic: args.channel} end
      resolve &R.root/3
    end
  end
end
