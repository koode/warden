defmodule Warden.Test.Ecto.GraphQL do
  @moduledoc false
  # A GraphQL schema over the Ecto suite: `issues` returns every issue unscoped, and the
  # object rule `can(Issues, :read)` decides which ones a client sees.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.Ecto.Authz, list_policy: :filter

  import Ecto.Query, only: [from: 2]

  alias Warden.Test.Ecto.{Comment, CommentFields, Comments, Issue, Issues}
  alias Warden.Test.Repo

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
