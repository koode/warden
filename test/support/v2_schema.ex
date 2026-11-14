defmodule Warden.Test.V2.Data do
  @moduledoc false

  def people do
    [
      %{id: "abby", name: "Abby", visible: true},
      %{id: "sam", name: "Sam", visible: false},
      %{id: "olivia", name: "Olivia", visible: true}
    ]
  end

  def person(id), do: Enum.find(people(), &(&1.id == id))

  def workspaces do
    [
      %{tenant_id: "t1", name: "Studio"},
      %{tenant_id: "t2", name: "Lab"},
      %{tenant_id: "t3", name: "Annex"}
    ]
  end
end

defmodule Warden.Test.V2.Schema do
  @moduledoc false
  # The v0.2 GraphQL surface: policies as object, field and argument rules, covered(),
  # on_deny:, tenant roles and batched checks over lists.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.V2.Authz, strict_mode: :all

  alias Warden.Test.Probe
  alias Warden.Test.V2.{Data, Doc, Docs}

  object :doc do
    authorize can(Docs, :read)

    field :id, non_null(:integer) do
      authorize covered()
    end

    field :body, :string do
      authorize covered()
    end

    field :owner, :person do
      authorize covered()
      resolve fn doc, _args, _resolution -> {:ok, Data.person(doc.owner_id)} end
    end

    field :admin_note, :string do
      authorize(tenant_role(:admin), on_deny: :null)
      resolve fn _doc, _args, _resolution -> {:ok, "note"} end
    end

    field :badge, non_null(:string) do
      authorize(tenant_role(:owner), on_deny: {:replace, "hidden"})
      resolve fn _doc, _args, _resolution -> {:ok, "owner badge"} end
    end
  end

  object :person do
    authorize check(:visible)

    field :id, :string do
      authorize covered()
    end

    field :name, :string do
      authorize covered()
    end
  end

  object :workspace do
    authorize tenant_role(:guest)

    field :name, :string do
      authorize covered()
    end

    field :guarded, :string do
      authorize all_of([tenant_role(:member), any_of([tenant_role(:admin), tenant_role(:guest)])])
      resolve fn _workspace, _args, _resolution -> {:ok, "member data"} end
    end
  end

  query do
    field :docs, list_of(:doc) do
      authorize public()

      resolve fn _args, resolution ->
        {:ok, Doc.all()} |> tap(fn _result -> Probe.hit(resolution, :docs) end)
      end
    end

    field :filtered_docs, list_of(non_null(:doc)) do
      authorize public()
      list_policy :filter
      resolve fn _args, _resolution -> {:ok, Doc.all()} end
    end

    field :people, list_of(:person) do
      authorize public()
      resolve fn _args, _resolution -> {:ok, Data.people()} end
    end

    field :workspaces, list_of(:workspace) do
      authorize authenticated()
      list_policy :filter
      resolve fn _args, _resolution -> {:ok, Data.workspaces()} end
    end

    field :reasoned, :string do
      authorize check(:reasoned)
      resolve fn _args, _resolution -> {:ok, "reasoned"} end
    end

    field :workspace_secret, :string do
      arg :workspace_id, non_null(:string)
      authorize tenant_role(:owner, tenant: {:arg, [:workspace_id]})

      resolve fn _args, resolution ->
        {:ok, "secret"} |> tap(fn _result -> Probe.hit(resolution, :workspace_secret) end)
      end
    end
  end

  mutation do
    field :update_doc, :doc do
      arg :id, non_null(:integer)
      authorize can(Docs, :write, arg: [:id])

      resolve fn %{id: id}, resolution ->
        Probe.hit(resolution, {:update_doc, id})
        {:ok, Doc.get(id)}
      end
    end

    field :archive_docs, :boolean do
      arg :ids, non_null(list_of(non_null(:integer)))
      authorize authenticated()
      authorize_args ids: can(Docs, :write, arg: [:ids])

      resolve fn %{ids: ids}, resolution ->
        Probe.hit(resolution, {:archive_docs, ids})
        {:ok, true}
      end
    end
  end

  subscription do
    field :doc_updated, :doc do
      arg :workspace_id, non_null(:string)
      authorize tenant_role(:guest, tenant: {:arg, [:workspace_id]})
      config fn args, _resolution -> {:ok, topic: "docs:" <> args.workspace_id} end
      resolve fn doc, _args, _resolution -> {:ok, doc} end
    end
  end
end
