defmodule Warden.Test.Resolvers do
  @moduledoc false
  alias Warden.Test.{Data, Probe}

  def me(_, _, %{context: ctx} = res) do
    Probe.hit(res, :me)
    {:ok, ctx[:current_user] && Data.user(ctx.current_user.id)}
  end

  def user(_, %{id: id}, res) do
    Probe.hit(res, {:user, id})
    {:ok, Data.user(id)}
  end

  def users(_, args, res) do
    Probe.hit(res, {:users, args})
    {:ok, Data.users()}
  end

  def posts(_, args, res) do
    Probe.hit(res, {:posts, args})
    {:ok, Data.posts()}
  end

  def node(_, %{id: id}, res) do
    Probe.hit(res, {:node, id})
    {:ok, Data.get(id)}
  end

  def search(_, _, res) do
    Probe.hit(res, :search)
    {:ok, Data.all()}
  end

  def secrets(_, _, res) do
    Probe.hit(res, :secrets)
    {:ok, Data.secrets()}
  end

  def secret_matrix(_, _, _), do: {:ok, [Data.secrets(), [hd(Data.secrets())], []]}

  def mixed_matrix(_, _, _) do
    [s1, _] = Data.secrets()
    [p1, _] = Data.posts()
    {:ok, [[p1, s1], [p1]]}
  end

  def author(post, _, _), do: {:ok, Data.user(post.author_id)}

  def friends(%{id: id}, _, _), do: {:ok, Enum.reject(Data.users(), &(&1.id == id))}

  def admin_stats(_, _, res) do
    Probe.hit(res, :admin_stats)
    {:ok, "42"}
  end

  def configured(_, _, res) do
    Probe.hit(res, :configured)
    {:ok, "configured"}
  end

  def delete_post(_, %{id: id}, res) do
    Probe.hit(res, {:delete_post, id})
    {:ok, true}
  end

  def create_post(_, args, res) do
    Probe.hit(res, {:create_post, args})
    {:ok, %{kind: :post, id: "p9", title: args.title, author_id: "u1", draft_notes: "n"}}
  end

  def leak_secret(_, _, res) do
    Probe.hit(res, :leak_secret)
    {:ok, hd(Data.secrets())}
  end

  def update_profile(_, args, res) do
    Probe.hit(res, {:update_profile, args})
    {:ok, Data.user("u2")}
  end

  def async_secret(_, _, _) do
    Absinthe.Resolution.Helpers.async(fn -> {:ok, hd(Data.secrets())} end)
  end

  def batch_secrets(_, _, _) do
    Absinthe.Resolution.Helpers.batch({__MODULE__, :load_secrets}, :all, fn batch ->
      {:ok, Map.fetch!(batch, :all)}
    end)
  end

  def load_secrets(_, _), do: %{all: Data.secrets()}

  def loader_secret(_, %{id: id}, %{context: %{loader: loader}}) do
    loader
    |> Dataloader.load(:kv, :secret, id)
    |> Absinthe.Resolution.Helpers.on_load(fn loader ->
      {:ok, Dataloader.get(loader, :kv, :secret, id)}
    end)
  end

  def kv_load(:secret, ids) do
    Map.new(ids, fn id -> {id, Data.get(id)} end)
  end

  def kv_load(:user, ids) do
    Map.new(ids, fn id -> {id, Data.get(id)} end)
  end

  def subscription_root(root, _, _), do: {:ok, root}

  # Publishes from inside a mutation, so the publisher's execution is live in the same
  # process while subscriber documents resolve.
  def rotate_secret(_, _, res) do
    Probe.hit(res, :rotate_secret)
    :ok = Absinthe.Subscription.publish(Warden.Test.Pubsub, hd(Data.secrets()), secret_rotated: "secrets")
    {:ok, true}
  end

  def resolve_kind(%{kind: kind}, _), do: kind
  def resolve_kind(_, _), do: nil
end

defmodule Warden.Test.Schema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Schema, authorizer: Warden.Test.Authz

  alias Warden.Test.Resolvers, as: R

  def context(ctx) do
    loader =
      Dataloader.new()
      |> Dataloader.add_source(:kv, Dataloader.KV.new(&R.kv_load/2))

    Map.put(ctx, :loader, loader)
  end

  def plugins, do: [Absinthe.Middleware.Dataloader | Absinthe.Plugin.defaults()]

  interface :node do
    field :id, non_null(:id)
    resolve_type &R.resolve_kind/2
  end

  interface :labeled do
    field :label, :string do
      authorize role(:editor)
    end

    resolve_type &R.resolve_kind/2
  end

  object :user do
    interfaces [:node, :labeled]
    authorize any_of([role(:viewer), check(:self)])

    field :id, non_null(:id)
    field :name, :string

    field :email, :string do
      authorize any_of([role(:admin), check(:self)])
    end

    # No own rule; the :labeled interface rule applies.
    field :label, :string do
      resolve fn user, _, _ -> {:ok, "label:" <> user.name} end
    end

    field :friends, list_of(non_null(:user)) do
      resolve &R.friends/3
    end
  end

  object :post do
    interfaces [:node]
    authorize permission("posts:read")

    field :id, non_null(:id)
    field :title, :string

    field :draft_notes, :string do
      authorize check(:owner)
    end

    field :author, :user, resolve: &R.author/3
  end

  object :secret do
    interfaces [:node]
    authorize role(:admin)

    field :id, non_null(:id)
    field :code, :string
  end

  union :search_result do
    types [:user, :post, :secret]
    resolve_type &R.resolve_kind/2
  end

  union :restricted_result do
    authorize role(:auditor)
    types [:user, :post]
    resolve_type &R.resolve_kind/2
  end

  enum :status do
    value :published
    value :draft
  end

  input_object :author_filter do
    field :name, :string

    field :internal_id, :id do
      authorize role(:admin)
    end
  end

  input_object :post_filter do
    field :title, :string

    field :include_drafts, :boolean, default_value: false do
      authorize role(:editor)
    end

    field :author, :author_filter
    field :authors, list_of(non_null(:author_filter))
    field :nested, :post_filter
  end

  input_object :profile_input do
    field :name, :string

    field :roles, list_of(:string) do
      authorize role(:admin)
    end
  end

  query do
    field :me, :user, resolve: &R.me/3

    field :user, :user do
      arg :id, non_null(:id)
      resolve &R.user/3
    end

    field :users, list_of(non_null(:user)) do
      authorize authenticated()
      arg :include_deleted, :boolean, default_value: false
      arg :status, :status, default_value: :published
      authorize_args include_deleted: role(:admin), status: role(:editor)
      resolve &R.users/3
    end

    field :posts, list_of(:post) do
      arg :filter, :post_filter
      arg :filters, list_of(:post_filter)
      resolve &R.posts/3
    end

    field :node, :node do
      arg :id, non_null(:id)
      resolve &R.node/3
    end

    field :search, list_of(:search_result), resolve: &R.search/3

    field :restricted, list_of(:restricted_result) do
      resolve fn _, _, _ -> {:ok, Warden.Test.Data.users() ++ Warden.Test.Data.posts()} end
    end

    field :secrets, list_of(:secret), resolve: &R.secrets/3

    field :filtered_secrets, list_of(:secret) do
      list_policy :filter
      resolve &R.secrets/3
    end

    field :strict_secrets, list_of(:secret) do
      list_policy :fail_list
      resolve &R.secrets/3
    end

    field :non_null_secrets, non_null(list_of(non_null(:secret))) do
      resolve &R.secrets/3
    end

    field :secret_matrix, list_of(list_of(:secret)), resolve: &R.secret_matrix/3

    field :secret_matrix_nn, list_of(list_of(non_null(:secret))) do
      resolve &R.secret_matrix/3
    end

    field :mixed_matrix, list_of(non_null(list_of(non_null(:node)))) do
      resolve &R.mixed_matrix/3
    end

    field :secret, :secret do
      resolve fn _, _, _ -> {:ok, hd(Warden.Test.Data.secrets())} end
    end

    field :required_secret, non_null(:secret) do
      resolve fn _, _, _ -> {:ok, hd(Warden.Test.Data.secrets())} end
    end

    field :async_secret, :secret, resolve: &R.async_secret/3
    field :batch_secrets, list_of(:secret), resolve: &R.batch_secrets/3

    field :loader_secret, :secret do
      arg :id, non_null(:id)
      resolve &R.loader_secret/3
    end

    field :admin_stats, :string do
      authorize role(:admin)
      resolve &R.admin_stats/3
    end

    field :configured, :string do
      authorize check(:configured)
      resolve &R.configured/3
    end

    field :open, :string do
      resolve fn _, _, _ -> {:ok, "open"} end
    end
  end

  mutation do
    field :delete_post, :boolean do
      authorize role(:admin)
      arg :id, non_null(:id)
      resolve &R.delete_post/3
    end

    field :create_post, :post do
      authorize role(:editor)
      arg :title, non_null(:string)
      arg :pinned, :boolean, default_value: false
      authorize_args pinned: role(:admin)
      resolve &R.create_post/3
    end

    field :update_profile, :user do
      authorize authenticated()
      arg :input, non_null(:profile_input)
      resolve &R.update_profile/3
    end

    field :rotate_secret, :boolean do
      authorize role(:admin)
      resolve &R.rotate_secret/3
    end

    field :leak_secret, :secret do
      authorize authenticated()
      resolve &R.leak_secret/3
    end
  end

  subscription do
    field :post_created, :post do
      config fn _args, _info -> {:ok, topic: "posts"} end
      resolve &R.subscription_root/3
    end

    field :secret_rotated, :secret do
      config fn _args, _info -> {:ok, topic: "secrets"} end
      resolve &R.subscription_root/3
    end

    field :shared_user, :user do
      config fn _args, _info -> {:ok, topic: "users", context_id: "global"} end
      resolve &R.subscription_root/3
    end

    field :admin_feed, :string do
      authorize role(:admin)
      arg :verbose, :boolean, default_value: false
      authorize_args verbose: role(:auditor)
      config fn _args, _info -> {:ok, topic: "admin"} end
      resolve &R.subscription_root/3
    end

    field :default_config, :post do
      resolve &R.subscription_root/3
    end
  end
end

defmodule Warden.Test.Pubsub do
  @moduledoc false
  # Minimal Absinthe.Subscription.Pubsub for tests: publishes results to the test
  # process registered as the pubsub owner.
  @behaviour Absinthe.Subscription.Pubsub

  def start_link do
    Absinthe.Subscription.start_link(__MODULE__)
  end

  def child_spec(_), do: Absinthe.Subscription.child_spec(__MODULE__)

  @impl true
  def node_name, do: to_string(node())

  @impl true
  def subscribe(topic) do
    Registry.register(__MODULE__.Topics, topic, [])
    :ok
  end

  @impl true
  def publish_mutation(_proxy_topic, _mutation_result, _subscribed_fields), do: :ok

  @impl true
  def publish_subscription(topic, data) do
    for {pid, _} <- Registry.lookup(__MODULE__.Topics, topic) do
      send(pid, {:subscription_data, topic, data})
    end

    :ok
  end
end
