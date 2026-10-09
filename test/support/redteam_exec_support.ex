defmodule Warden.RedteamExec.Authz do
  @moduledoc false
  # Authorizer for the execution / subscription / contract red-team suite. Most
  # callbacks can be bent per test through the context or the process dictionary
  # (deny/1 gets no context).
  use Warden.Authorizer,
    roles: [:admin, :editor, :viewer],
    permissions: ["secrets:read", "posts:read", "posts:write"],
    role_hierarchy: %{admin: [:editor], editor: [:viewer]},
    role_permissions: %{
      admin: :all,
      editor: ["posts:write", "posts:read"],
      viewer: ["posts:read"]
    },
    checks: [:tenant, :ctx_org, :odd, :boom, :self]

  @impl true
  def subject(%{subject_fun: fun} = context), do: fun.(context)
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, context) do
    case context[:roles_fun] do
      nil -> if is_map(user), do: Map.get(user, :roles, []), else: []
      fun -> fun.(user, context)
    end
  end

  @impl true
  def permissions(user, context) do
    case context[:perms_fun] do
      nil -> if is_map(user), do: Map.get(user, :permissions, []), else: []
      fun -> fun.(user, context)
    end
  end

  @impl true
  def check(:tenant, %Warden.Check{actor: actor, value: value}) do
    is_map(value) and is_map(actor.subject) and
      Map.get(value, :tenant) == Map.get(actor.subject, :tenant)
  end

  def check(:ctx_org, %Warden.Check{context: context, value: value}) do
    is_map(value) and Map.get(value, :org) == context[:org]
  end

  def check(:odd, %Warden.Check{context: context}), do: Map.get(context, :check_result, false)
  def check(:boom, _), do: raise("check exploded")

  def check(:self, %Warden.Check{actor: actor, value: value}) do
    is_map(value) and is_map(actor.subject) and Map.get(value, :id) == actor.subject[:id]
  end

  @impl true
  def deny(denial) do
    case Process.get(:rx_deny) do
      nil -> Warden.Authorizer.default_deny(denial, __warden_catalog__())
      fun -> fun.(denial)
    end
  end

  # Port to the actor_key/2 callback (opt-in sharing). Without a per-test key it opts
  # out (nil), the same as an authorizer that does not define the callback.
  @impl true
  def actor_key(actor, _context) do
    case Process.get(:rx_actor_key) do
      nil -> nil
      fun -> fun.(actor)
    end
  end
end

defmodule Warden.RedteamExec.NilCatalogAuthz do
  @moduledoc false
  # No permission catalog: any permission term from user data is accepted.
  use Warden.Authorizer,
    roles: [:admin, :viewer],
    role_hierarchy: %{admin: [:viewer]},
    role_permissions: %{admin: :all}

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: Map.get(user, :roles, [])

  @impl true
  def permissions(user, _context), do: Map.get(user, :permissions, [])
end

defmodule Warden.RedteamExec.Data do
  @moduledoc false

  def secret, do: %{kind: :rx_secret, id: "s1", code: "ALPHA"}
  def secret2, do: %{kind: :rx_secret, id: "s2", code: "BRAVO"}
  def post, do: %{kind: :rx_post, id: "p1", title: "Hello", notes: "editor-notes"}

  def tdoc(tenant),
    do: %{kind: :rx_tdoc, id: "t-#{tenant}", tenant: tenant, body: "body-#{tenant}"}

  def odoc(org), do: %{kind: :rx_odoc, id: "o-#{org}", org: org, body: "body-#{org}"}

  def user(roles, opts \\ []) do
    %{id: Keyword.get(opts, :id, "u1"), roles: List.wrap(roles)}
    |> Map.merge(Map.new(Keyword.delete(opts, :id)))
  end
end

defmodule Warden.RedteamExec.CacheMiddleware do
  @moduledoc false
  # A user "cache" middleware that short-circuits resolution with a stored value.
  @behaviour Absinthe.Middleware
  def call(res, value), do: Absinthe.Resolution.put_result(res, {:ok, value})
end

defmodule Warden.RedteamExec.Res do
  @moduledoc false
  alias Warden.RedteamExec.Data

  def probe(tag, value) do
    fn _parent, _args, res ->
      hit(res, tag)
      {:ok, value}
    end
  end

  def hit(%{context: context}, tag) do
    if pid = context[:test_pid], do: send(pid, {:ran, tag})
  end

  def kind(%{kind: kind}, _), do: kind
  def kind(_, _), do: nil

  def kv_load(_batch, ids) do
    Map.new(ids, fn id -> {id, if(id == "s1", do: Data.secret(), else: nil)} end)
  end
end

defmodule Warden.RedteamExec.Schema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Schema, authorizer: Warden.RedteamExec.Authz

  import Absinthe.Resolution.Helpers, only: [async: 1, batch: 3, on_load: 2]

  alias Warden.RedteamExec.{Data, Res}

  def context(ctx) do
    loader =
      Dataloader.new()
      |> Dataloader.add_source(:kv, Dataloader.KV.new(&Res.kv_load/2))

    Map.put_new(ctx, :loader, loader)
  end

  def plugins, do: [Absinthe.Middleware.Dataloader | Absinthe.Plugin.defaults()]

  object :rx_secret do
    authorize role(:admin)
    field :id, :id
    field :code, :string
  end

  object :rx_tdoc do
    authorize check(:tenant)
    field :id, :id
    field :body, :string
  end

  object :rx_odoc do
    authorize check(:ctx_org)
    field :id, :id
    field :body, :string
  end

  object :rx_post do
    field :id, :id
    field :title, :string

    field :notes, :string do
      authorize role(:editor)
    end
  end

  union :rx_result do
    types [:rx_secret, :rx_post]
    resolve_type &Res.kind/2
  end

  object :rx_box do
    field :secrets, list_of(:rx_secret) do
      resolve fn _, _, _ -> {:ok, [Data.secret(), Data.secret2()]} end
    end

    field :locked, non_null(:string) do
      authorize role(:admin)
      resolve fn _, _, _ -> {:ok, "locked"} end
    end

    field :label, :string do
      resolve fn _, _, _ -> {:ok, "box"} end
    end
  end

  input_object :rx_filter do
    field :include_hidden, :boolean do
      authorize role(:admin)
    end

    field :nested, :rx_filter
    field :term, :string
  end

  query do
    field :secret, :rx_secret do
      arg :id, :id

      resolve fn _, args, _ ->
        case args[:id] do
          "s1" -> {:ok, Data.secret()}
          _ -> {:ok, nil}
        end
      end
    end

    field :box, :rx_box do
      resolve fn _, _, _ -> {:ok, %{}} end
    end

    field :strict_box, non_null(:rx_box) do
      resolve fn _, _, _ -> {:ok, %{}} end
    end

    field :admin_only, :string do
      authorize role(:admin)
      resolve Res.probe(:admin_only, "admin-data")
    end

    field :authed, :string do
      authorize authenticated()
      resolve Res.probe(:authed, "authed-data")
    end

    field :perm_field, :string do
      authorize permission("secrets:read")
      resolve Res.probe(:perm_field, "perm-data")
    end

    field :odd_check, :string do
      authorize check(:odd)
      resolve Res.probe(:odd_check, "odd-data")
    end

    field :boom_check, :string do
      authorize check(:boom)
      resolve Res.probe(:boom_check, "boom-data")
    end

    field :async_admin, :string do
      authorize role(:admin)

      resolve fn _, _, res ->
        async(fn ->
          Res.hit(res, :async_admin)
          {:ok, "async-data"}
        end)
      end
    end

    field :batch_admin, :string do
      authorize role(:admin)

      resolve fn _, _, res ->
        batch({__MODULE__, :batch_load, res.context[:test_pid]}, "x", fn results ->
          {:ok, Map.get(results, "x")}
        end)
      end
    end

    field :loader_admin, :rx_secret do
      authorize role(:admin)

      resolve fn _, _, %{context: %{loader: loader}} = res ->
        Res.hit(res, :loader_admin)

        loader
        |> Dataloader.load(:kv, :secret, "s1")
        |> on_load(fn loader -> {:ok, Dataloader.get(loader, :kv, :secret, "s1")} end)
      end
    end

    field :loader_secret, :rx_secret do
      resolve fn _, _, %{context: %{loader: loader}} ->
        loader
        |> Dataloader.load(:kv, :secret, "s1")
        |> on_load(fn loader -> {:ok, Dataloader.get(loader, :kv, :secret, "s1")} end)
      end
    end

    field :async_secret, non_null(:rx_secret) do
      resolve fn _, _, _ -> async(fn -> {:ok, Data.secret()} end) end
    end

    field :cached_secret, :rx_secret do
      middleware Warden.RedteamExec.CacheMiddleware, Data.secret()
      resolve fn _, _, _ -> {:ok, nil} end
    end

    field :cached_admin, :string do
      authorize role(:admin)
      middleware Warden.RedteamExec.CacheMiddleware, "cached-admin-data"
    end

    field :replaced, :rx_secret do
      authorize role(:admin)
      resolve Res.probe(:replaced, nil)
    end

    field :replaced_post, :rx_post do
      authorize role(:admin)
      resolve Res.probe(:replaced_post, nil)
    end

    field :replaced_list, list_of(:rx_secret) do
      authorize role(:admin)
      list_policy :filter
      resolve Res.probe(:replaced_list, [])
    end

    field :search, list_of(:rx_result) do
      resolve fn _, _, _ -> {:ok, [Data.secret(), Data.post()]} end
    end

    field :guarded_arg, :string do
      arg :filter, :rx_filter
      resolve Res.probe(:guarded_arg, "ok")
    end
  end

  mutation do
    field :nuke, :boolean do
      authorize role(:admin)
      resolve Res.probe(:nuke, true)
    end

    field :nuke_arg, :boolean do
      arg :filter, :rx_filter
      resolve Res.probe(:nuke_arg, true)
    end

    field :create_secret, :rx_secret do
      # Deliberately open to every caller; declared so, which silences Warden's
      # compile-time warning about mutations guarded only by their return type.
      authorize public()
      resolve Res.probe(:create_secret, Data.secret())
    end
  end

  subscription do
    field :rx_secret_updated, :rx_secret do
      config fn _, _ -> {:ok, topic: "rx-s"} end
    end

    field :rx_tdoc_updated, :rx_tdoc do
      config fn _, _ -> {:ok, topic: "rx-t", context_id: "global"} end
    end

    field :rx_odoc_updated, :rx_odoc do
      config fn _, _ -> {:ok, topic: "rx-o", context_id: "global"} end
    end

    field :rx_post_shared, :rx_post do
      config fn _, _ -> {:ok, topic: "rx-p", context_id: "global"} end
    end

    field :rx_post_int_ctx, :rx_post do
      config fn _, _ -> {:ok, topic: "rx-pi", context_id: 42} end
    end

    field :rx_post_atom_ctx, :rx_post do
      config fn _, _ -> {:ok, topic: "rx-pa", context_id: :global} end
    end

    field :rx_post_false_ctx, :rx_post do
      config fn _, _ -> {:ok, topic: "rx-pf", context_id: false} end
    end

    field :rx_post_list_topics, :rx_post do
      config fn _, _ -> {:ok, topic: ["rx-l1", "rx-l2"], context_id: "global"} end
    end

    field :rx_post_doc_id, :rx_post do
      config fn _, _ -> {:ok, topic: "rx-pd", context_id: "global", document_id: "fixed"} end
    end

    field :rx_admin_feed, :rx_post do
      authorize role(:admin)

      config fn _, %{context: context} ->
        if pid = context[:test_pid], do: send(pid, {:ran, :rx_admin_feed_config})
        {:ok, topic: "rx-a"}
      end
    end

    field :rx_admin_feed_error, :rx_post do
      authorize role(:admin)
      config fn _, _ -> {:error, "config refused"} end
    end

    field :rx_admin_feed_raise, :rx_post do
      authorize role(:admin)
      config fn _, _ -> raise "config exploded" end
    end

    field :rx_filtered_feed, :rx_post do
      arg :filter, :rx_filter
      config fn _, _ -> {:ok, topic: "rx-f"} end
    end

    field :rx_listed_feed, :rx_post do
      arg :filters, list_of(:rx_filter)
      config fn _, _ -> {:ok, topic: "rx-lf"} end
    end

    field :rx_result_feed, :rx_result do
      config fn _, _ -> {:ok, topic: "rx-r", context_id: "global"} end
    end

    field :rx_box_feed, :rx_box do
      config fn _, _ -> {:ok, topic: "rx-b", context_id: "global"} end
    end

    field :rx_nuked, :boolean do
      config fn _, _ -> {:ok, topic: "rx-n"} end
      trigger [:nuke, :nuke_arg], topic: fn _ -> "rx-n" end
    end

    field :rx_one_arity, :rx_post do
      authorize role(:admin)
      config fn _args -> {:ok, topic: "rx-1"} end
    end
  end

  def batch_load(test_pid, _ids) do
    if test_pid, do: send(test_pid, {:ran, :batch_admin})
    %{"x" => "batch-data"}
  end
end

defmodule Warden.RedteamExec.Helpers do
  @moduledoc false
  alias Warden.Test.Pubsub

  @schema Warden.RedteamExec.Schema

  def run(doc, user, opts \\ []) do
    schema = Keyword.get(opts, :schema, @schema)
    extra = Keyword.get(opts, :context, %{})
    variables = Keyword.get(opts, :variables, %{})
    context = Map.merge(%{current_user: user, test_pid: self(), pubsub: Pubsub}, extra)

    case Absinthe.run(doc, schema, context: context, variables: variables) do
      {:ok, result} -> result
      other -> raise "unexpected result: #{inspect(other)}"
    end
  end

  def subscribe(doc, user, extra \\ %{}, opts \\ []) do
    schema = Keyword.get(opts, :schema, @schema)
    variables = Keyword.get(opts, :variables, %{})
    context = Map.merge(%{pubsub: Pubsub, current_user: user, test_pid: self()}, extra)

    {:ok, result} = Absinthe.run(doc, schema, context: context, variables: variables)

    # Absinthe's result spec has no "subscribed" key, so Dialyzer rejects matching on it.
    case Map.fetch(result, "subscribed") do
      {:ok, topic} ->
        :ok = Pubsub.subscribe(topic)
        {:ok, topic}

      :error ->
        {:error, Map.fetch!(result, :errors)}
    end
  end

  def publish(value, topics), do: :ok = Absinthe.Subscription.publish(Pubsub, value, topics)

  def receive_data(topic, timeout \\ 500) do
    receive do
      {:subscription_data, ^topic, data} -> data
    after
      timeout -> :none
    end
  end

  def ran do
    receive do
      {:ran, tag} -> [tag | ran()]
    after
      0 -> []
    end
  end

  def contains?(data, needle) when is_binary(data), do: data == needle

  def contains?(data, needle) when is_map(data),
    do: Enum.any?(data, fn {_, v} -> contains?(v, needle) end)

  def contains?(data, needle) when is_list(data), do: Enum.any?(data, &contains?(&1, needle))
  def contains?(_, _), do: false
end
