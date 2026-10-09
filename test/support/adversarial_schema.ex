defmodule Warden.Test.Adversarial.Swap do
  @moduledoc false
  # User middleware placed after Absinthe.Resolution that swaps the resolved value for a
  # restricted object.
  @behaviour Absinthe.Middleware

  alias Warden.Test.Data

  def call(res, _), do: %{res | value: hd(Data.secrets())}
end

defmodule Warden.Test.Adversarial.Appender do
  @moduledoc false
  # User middleware that, at runtime, appends another middleware to the end of the
  # chain, after Warden's post middleware.
  @behaviour Absinthe.Middleware
  def call(res, _), do: %{res | middleware: res.middleware ++ [Warden.Test.Adversarial.Swap]}
end

defmodule Warden.Test.Adversarial.Escalate do
  @moduledoc false
  # User middleware that rewrites the context mid-execution to an admin.
  @behaviour Absinthe.Middleware

  alias Warden.Test.Data

  def call(res, _) do
    %{res | context: Map.put(res.context, :current_user, Data.as(:admin, "u1"))}
  end
end

defmodule Warden.Test.Adversarial.Resolvers do
  @moduledoc false
  alias Warden.Test.{Data, Probe}

  def secret(_, _, res) do
    Probe.hit(res, :secret)
    {:ok, hd(Data.secrets())}
  end

  def open(_, _, _), do: {:ok, "open"}
  def single_secret(_, _, _), do: {:ok, hd(Data.secrets())}
  def dossier(_, _, _), do: {:ok, %{kind: :dossier, id: "d1", body: "classified"}}
  def unknown_kind(_, _, _), do: {:ok, %{kind: :mystery, id: "m1"}}

  def deferred_secret(_, _, _) do
    {:middleware, Absinthe.Resolution, fn _, _, _ -> {:ok, hd(Data.secrets())} end}
  end

  def publish_rotate(_, _, res) do
    Probe.hit(res, :publish_rotate)

    :ok =
      Absinthe.Subscription.publish(Warden.Test.Pubsub, hd(Data.secrets()),
        secret_rotated: "secrets"
      )

    {:ok, true}
  end

  def kind(%{kind: kind}, _) when kind in [:secret, :dossier], do: kind
  def kind(_, _), do: nil
end

defmodule Warden.Test.Adversarial.Schema do
  @moduledoc false
  use Absinthe.Schema
  use Warden.Absinthe, authorizer: Warden.Test.Authz

  alias Warden.Test.Adversarial.Resolvers, as: R

  # A user's middleware/3 that tries every trick at compile time.
  def middleware(middleware, %{identifier: :tampered}, _object) do
    middleware ++ [Warden.Test.Adversarial.Swap]
  end

  def middleware(_middleware, %{identifier: :dropped}, _object) do
    # Drops everything and installs only a resolver.
    [{Absinthe.Resolution, &R.secret/3}]
  end

  def middleware(middleware, %{identifier: :closure}, _object) do
    # A closure cannot be escaped, so Absinthe shims this field at runtime.
    middleware ++ [fn res, _ -> res end]
  end

  def middleware(middleware, %{identifier: :appended}, _object) do
    middleware ++ [Warden.Test.Adversarial.Appender]
  end

  def middleware(middleware, %{identifier: :escalate}, _object) do
    middleware ++ [Warden.Test.Adversarial.Escalate]
  end

  def middleware(middleware, _field, _object), do: middleware

  object :secret do
    authorize role(:admin)
    field :id, :id
    field :code, :string
  end

  interface :classified do
    authorize role(:admin)
    field :id, :id
    resolve_type &R.kind/2
  end

  object :dossier do
    interfaces [:classified]
    field :id, :id
    field :body, :string
  end

  query do
    field :open, :string, resolve: &R.open/3

    field :tampered, :string do
      resolve &R.open/3
    end

    field :tampered_object, :secret do
      resolve &R.open/3
    end

    field :appended, :secret do
      resolve fn _, _, _ -> {:ok, nil} end
    end

    field :dropped, :secret do
      authorize role(:admin)
      resolve &R.secret/3
    end

    field :closure, :secret do
      resolve &R.secret/3
    end

    field :escalate, :string do
      authorize authenticated()
      resolve &R.open/3
    end

    field :admin_only, :string do
      authorize role(:admin)
      resolve &R.open/3
    end

    field :not_a_list, list_of(:secret) do
      resolve &R.single_secret/3
    end

    field :deferred, :secret, resolve: &R.deferred_secret/3

    field :dossier, :dossier, resolve: &R.dossier/3
    field :classified, :classified, resolve: &R.dossier/3
    field :mystery, :classified, resolve: &R.unknown_kind/3
  end

  mutation do
    field :publish_rotate, :boolean do
      authorize role(:admin)
      resolve &R.publish_rotate/3
    end
  end
end
