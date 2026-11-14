defmodule Warden.Test.Ecto.GraphQL do
  @moduledoc false
  # A GraphQL schema over the Ecto suite: `issues` returns every issue unscoped, and the
  # object rule `can(Issues, :read)` decides which ones a client sees.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.Ecto.Authz, list_policy: :filter

  import Absinthe.Resolution.Helpers, only: [on_load: 2]
  import Ecto.Query, only: [from: 2]

  alias Warden.Test.Ecto.{Comment, CommentFields, Comments, Issue, Issues}
  alias Warden.Test.Repo

  # Absinthe's Dataloader plugin replaces `context.loader` on every resolution pass.
  def plugins, do: [Absinthe.Middleware.Dataloader | Absinthe.Plugin.defaults()]

  def context(context) do
    source = Dataloader.KV.new(fn _batch, keys -> Map.new(keys, &{&1, &1}) end)
    Map.put_new(context, :loader, Dataloader.add_source(Dataloader.new(), :kv, source))
  end

  object :issue do
    authorize can(Issues, :read)
    field :id, :id
    field :title, :string
  end

  object :comment do
    authorize can(Comments, :read)
    redact_with CommentFields
    field :id, :id
    field :body, :string
  end

  query do
    field :issue, :issue do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _resolution -> {:ok, Repo.get(Issue, id)} end
    end

    field :comment, :comment do
      arg :id, non_null(:id)
      resolve fn %{id: id}, _resolution -> {:ok, Repo.get(Comment, id)} end
    end

    field :issues, list_of(:issue) do
      resolve fn _args, _resolution ->
        query = from(issue in Issue, order_by: issue.id)
        {:ok, Repo.all(query)}
      end
    end

    # Loads through `Warden.Ecto.all/5` with the execution's own actor, which the object
    # rule then decides with.
    field :scoped_issues, list_of(:issue) do
      resolve fn _args, resolution ->
        query = from(issue in Issue, order_by: issue.id)
        actor = Warden.Absinthe.actor(resolution)
        {:ok, Warden.Ecto.all(Repo, query, actor, :read)}
      end
    end

    # The same list, loaded after a Dataloader round trip: its rows are decided in a later
    # resolution pass, under a context whose `:loader` changed.
    field :scoped_issues_after_load, list_of(:issue) do
      resolve fn _args, %{context: %{loader: loader}} = resolution ->
        loader
        |> Dataloader.load(:kv, :tick, 1)
        |> on_load(fn _loaded ->
          query = from(issue in Issue, order_by: issue.id)
          actor = Warden.Absinthe.actor(resolution)
          {:ok, Warden.Ecto.all(Repo, query, actor, :read)}
        end)
      end
    end
  end

  mutation do
    field :rename_issue, :issue do
      arg :id, non_null(:id)
      arg :title, non_null(:string)
      authorize can(Issues, :write, arg: [:id])

      resolve fn %{id: id, title: title}, %{context: context} ->
        send(context.test_pid, {:resolved, :rename_issue, id})
        issue = Repo.get!(Issue, id)
        Repo.update(Ecto.Changeset.change(issue, title: title))
      end
    end
  end
end
