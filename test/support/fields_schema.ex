defmodule Warden.Test.Fields.Resolvers do
  @moduledoc false
  # Resolvers of the field-policy schemas. Values come from the context, so property
  # tests can hand in random structs.

  alias Warden.Test.Fields.Comment

  def comments(_args, resolution), do: {:ok, resolution.context.comments}
  def first_comment(_args, resolution), do: {:ok, List.first(resolution.context.comments)}
  def comment_grid(_args, resolution), do: {:ok, Enum.chunk_every(resolution.context.comments, 2)}
  def nodes(_args, resolution), do: {:ok, Map.get(resolution.context, :nodes, [])}
  def issue(_args, resolution), do: {:ok, resolution.context.issue}
  def cards(_args, resolution), do: {:ok, Map.get(resolution.context, :cards, [])}

  # The body as a custom resolver reads it, reported to the test.
  def seen_body(comment, _args, resolution) do
    notify(resolution.context, {:resolver_saw, comment.id, comment.body})
    {:ok, comment.body}
  end

  # Even ids are trashed.
  def kv_load(:comment, ids), do: Map.new(ids, &{&1, loaded_comment(&1)})

  defp loaded_comment(id) do
    trashed_at = if rem(id, 2) == 0, do: ~U[2026-11-01 10:00:00Z], else: nil

    %Comment{
      id: id,
      workspace_id: "t1",
      author_id: "abby",
      body: "loaded #{id}",
      trashed_at: trashed_at
    }
  end

  def loaded(comments, ids),
    do: Map.new(ids, fn id -> {id, Enum.find(comments, &(&1.id == id))} end)

  def resolve_type(%Comment{}, _resolution), do: :comment
  def resolve_type(%Warden.Test.Fields.UserCard{}, _resolution), do: :user_card
  def resolve_type(%Warden.Test.Fields.Issue{}, _resolution), do: :issue
  def resolve_type(_value, _resolution), do: nil

  defp notify(%{test_pid: pid}, message) when is_pid(pid), do: send(pid, message)
  defp notify(_context, _message), do: :ok
end

defmodule Warden.Test.Fields.Schema do
  @moduledoc false
  # `redact_with` on comments (with a batched object rule), user cards and issues (no
  # object rule), behind an interface and a union, in nested lists, through Dataloader,
  # async and batch, in a mutation payload and a subscription.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.Fields.Authz

  import Absinthe.Resolution.Helpers, only: [async: 1, batch: 3, on_load: 2]

  alias Warden.Test.Fields.{CommentFields, IssueFields, Resolvers, UserCardFields}

  interface :node do
    field :id, non_null(:id)
    resolve_type &Resolvers.resolve_type/2
  end

  union :search_result do
    types [:comment, :user_card]
    resolve_type &Resolvers.resolve_type/2
  end

  object :comment do
    interface :node
    authorize check(:readable)
    redact_with CommentFields

    field :id, non_null(:id)
    field :body, non_null(:string)
    field :anchor, :string
    field :author_id, :string
    field :workspace_id, :string

    field :seen_body, :string do
      resolve &Resolvers.seen_body/3
    end
  end

  object :user_card do
    interface :node
    redact_with UserCardFields

    field :id, non_null(:id)
    field :name, :string
    field :timezone, :string
    field :email, :string
  end

  object :issue do
    interface :node
    redact_with IssueFields

    field :id, non_null(:id)
    field :title, :string
    field :comments, list_of(:comment)
    field :cards, list_of(:user_card)
  end

  object :comment_payload do
    field :comment, :comment
  end

  query do
    field :comments, list_of(:comment), resolve: &Resolvers.comments/2
    field :comment, :comment, resolve: &Resolvers.first_comment/2
    field :comment_grid, list_of(list_of(non_null(:comment))), resolve: &Resolvers.comment_grid/2

    field :filtered_comments, list_of(non_null(:comment)) do
      list_policy :filter
      resolve &Resolvers.comments/2
    end

    field :nodes, list_of(:node), resolve: &Resolvers.nodes/2
    field :search, list_of(:search_result), resolve: &Resolvers.nodes/2
    field :issue, :issue, resolve: &Resolvers.issue/2
    field :cards, list_of(:user_card), resolve: &Resolvers.cards/2

    field :async_comments, list_of(:comment) do
      resolve fn _args, resolution ->
        async(fn -> Resolvers.comments(%{}, resolution) end)
      end
    end

    field :batched_comment, :comment do
      arg :id, non_null(:integer)

      resolve fn %{id: id}, resolution ->
        comments = resolution.context.comments

        batch({Resolvers, :loaded, comments}, id, fn loaded ->
          {:ok, Map.get(loaded, id)}
        end)
      end
    end

    field :loaded_comment, :comment do
      arg :id, non_null(:integer)

      resolve fn %{id: id}, %{context: %{loader: loader}} ->
        loader
        |> Dataloader.load(:kv, :comment, id)
        |> on_load(fn loader -> {:ok, Dataloader.get(loader, :kv, :comment, id)} end)
      end
    end
  end

  mutation do
    field :edit_comment, :comment_payload do
      authorize authenticated()

      resolve fn _args, resolution ->
        {:ok, comment} = Resolvers.first_comment(%{}, resolution)
        payload = %{comment: comment}
        {:ok, payload}
      end
    end
  end

  subscription do
    field :comment_updated, :comment do
      authorize authenticated()
      config fn _args, _resolution -> {:ok, topic: "fields:comments"} end
    end
  end

  def context(context) do
    loader = Dataloader.add_source(Dataloader.new(), :kv, Dataloader.KV.new(&Resolvers.kv_load/2))
    Map.put(context, :loader, loader)
  end

  def plugins, do: [Absinthe.Middleware.Dataloader | Absinthe.Plugin.defaults()]
end

defmodule Warden.Test.Fields.AcrossSchema do
  @moduledoc false
  # Cross-parent batching: one comment per post, decided and redacted for every post at
  # once.
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.Fields.Authz, batch_across_parents: true

  alias Warden.Test.Fields.CommentFields

  object :comment do
    authorize check(:readable)
    redact_with CommentFields

    field :id, non_null(:id)
    field :body, non_null(:string)
    field :author_id, :string
  end

  object :post do
    field :id, non_null(:id)
    field :comment, :comment
  end

  query do
    field :posts, list_of(:post) do
      resolve fn _args, resolution ->
        posts = Enum.map(resolution.context.comments, &%{id: &1.id, comment: &1})
        {:ok, posts}
      end
    end
  end
end
