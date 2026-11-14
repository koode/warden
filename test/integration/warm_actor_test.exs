defmodule Warden.Test.WarmActor.Authz do
  @moduledoc false
  # Reports every read of tenants and tenant roles to the test process.
  use Warden.Authorizer, roles: [:staff], tenant_roles: [:member]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(_user, _context), do: []

  @impl true
  def tenants(%Warden.Actor{subject: user}, context) do
    send(context.test_pid, :tenants_read)
    user |> Map.get(:memberships, %{}) |> Map.keys()
  end

  @impl true
  def tenant_roles(user, tenant, context) do
    send(context.test_pid, {:tenant_roles_read, tenant})
    user |> Map.get(:memberships, %{}) |> Map.get(tenant, [])
  end

  @impl true
  def tenant_of(%{workspace_id: workspace_id}), do: workspace_id
  def tenant_of(_value), do: nil
end

defmodule Warden.Test.WarmActor.Warm do
  @moduledoc false
  # The warm functions of the schemas below; each reports the actor it was given.

  alias Warden.Actor

  def warm(%Actor{} = actor, context) do
    send(context.test_pid, {:warmed, actor.instance})
    {tenants, actor} = Actor.cached_tenants(actor, context)
    Actor.preload_tenant_roles(actor, tenants, context)
  end

  def swap(%Actor{} = actor, context) do
    send(context.test_pid, {:warmed, actor.instance})
    Actor.build(actor.authorizer, context)
  end

  def other_bounds(%Actor{} = actor, _context), do: %{actor | bounds: %{team_ids: [1]}}

  def not_an_actor(%Actor{subject: user}, _context), do: {:ok, user}
end

defmodule Warden.Absinthe.WarmActorTest do
  # `use Warden.Absinthe, warm_actor: ...` fills the cache of each execution's actor once,
  # right after it is built, and may never hand back another actor. Not async:
  # subscriptions share the test Pubsub registry.
  use ExUnit.Case, async: false

  import Warden.Test.CompileHelpers

  alias Absinthe.Phase.Document.Execution.Resolution
  alias Absinthe.Pipeline
  alias Warden.Test.Pubsub
  alias Warden.Test.RedteamV2.Card

  @body """
    object :card do
      authorize tenant_role(:member)
      field :id, non_null(:integer)
    end

    query do
      field :cards, list_of(:card) do
        authorize public()

        resolve fn _args, resolution ->
          actor = Warden.Absinthe.actor(resolution)
          send(resolution.context.test_pid, {:tenants, Warden.Actor.tenants(actor, resolution.context)})
          {:ok, Warden.Test.RedteamV2.Card.all()}
        end
      end

      field :plain_cards, list_of(:card) do
        authorize public()
        resolve fn _args, _resolution -> {:ok, Warden.Test.RedteamV2.Card.all()} end
      end
    end

    subscription do
      field :card_added, :card do
        authorize public()
        config fn _args, _info -> {:ok, topic: "cards"} end

        resolve fn card, _args, resolution ->
          send(resolution.context.test_pid, {:publish_actor, Warden.Absinthe.actor(resolution)})
          {:ok, card}
        end
      end
    end
  """

  @both %{id: "abby", memberships: %{"t1" => [:member], "t2" => [:member]}}

  setup_all do
    authorizer = "authorizer: Warden.Test.WarmActor.Authz"

    schemas =
      for warm <- [:warm, :swap, :other_bounds, :not_an_actor], into: %{} do
        opts = "#{authorizer}, warm_actor: &Warden.Test.WarmActor.Warm.#{warm}/2"
        {warm, compile_schema(@body, opts)}
      end

    tuple_opts = "#{authorizer}, warm_actor: {Warden.Test.WarmActor.Warm, :warm}"
    schemas = Map.put(schemas, :tuple, compile_schema(@body, tuple_opts))
    schemas = Map.put(schemas, :none, compile_schema(@body, authorizer))
    %{schemas: schemas}
  end

  defp context(user \\ @both), do: %{current_user: user, test_pid: self(), pubsub: Pubsub}

  defp drain(collected \\ []) do
    receive do
      message when message == :tenants_read or elem(message, 0) == :tenant_roles_read ->
        drain([message | collected])
    after
      0 -> Enum.reverse(collected)
    end
  end

  describe "one execution" do
    test "reads tenants and tenant roles once, in the warm function", %{schemas: schemas} do
      for schema <- [schemas.warm, schemas.tuple] do
        {:ok, %{data: %{"cards" => cards}}} =
          Absinthe.run("{ cards { id } }", schema, context: context())

        assert cards == [%{"id" => 1}, %{"id" => 2}, %{"id" => 3}]
        assert_received {:warmed, instance} when is_reference(instance)
        refute_received {:warmed, _instance}
        assert_received {:tenants, ["t1", "t2"]}

        reads = drain()

        assert Enum.sort(reads) == [
                 :tenants_read,
                 {:tenant_roles_read, "t1"},
                 {:tenant_roles_read, "t2"}
               ]
      end
    end

    test "without warm_actor nothing is warmed", %{schemas: schemas} do
      {:ok, _result} = Absinthe.run("{ cards { id } }", schemas.none, context: context())
      refute_received {:warmed, _instance}
    end

    test "runs in the lazy build of a pipeline without plugin callbacks", %{schemas: schemas} do
      pipeline =
        schemas.warm
        |> Pipeline.for_document(context: context())
        |> Pipeline.replace(Resolution, {Resolution, plugin_callbacks: false})

      {:ok, %{result: %{data: %{"plainCards" => cards}}}, _phases} =
        Pipeline.run("{ plainCards { id } }", pipeline)

      assert cards == [%{"id" => 1}, %{"id" => 2}, %{"id" => 3}]
      assert_received {:warmed, _instance}
      refute_received {:warmed, _instance}
      reads = drain()
      assert Enum.count(reads, &(&1 == :tenants_read)) == 1
    end
  end

  describe "a warm function that changes the actor" do
    test "a new actor is refused", %{schemas: schemas} do
      assert_raise Warden.PolicyError, ~r/returned another actor/, fn ->
        Absinthe.run("{ cards { id } }", schemas.swap, context: context())
      end
    end

    test "other bounds are refused", %{schemas: schemas} do
      assert_raise Warden.PolicyError, ~r/returned another actor/, fn ->
        Absinthe.run("{ cards { id } }", schemas.other_bounds, context: context())
      end
    end

    test "an answer that is not an actor is refused by its shape only", %{schemas: schemas} do
      error =
        assert_raise Warden.PolicyError, ~r/must return a %Warden.Actor{}/, fn ->
          Absinthe.run("{ cards { id } }", schemas.not_an_actor, context: context())
        end

      refute error.message =~ "abby"
    end
  end

  describe "subscriptions" do
    defp pushes(topic, collected \\ []) do
      receive do
        {:subscription_data, ^topic, data} -> pushes(topic, [data | collected])
      after
        200 -> Enum.reverse(collected)
      end
    end

    test "the subscribe-time checks and every publish warm their own actor", %{
      schemas: schemas
    } do
      {:ok, %{"subscribed" => topic}} =
        Absinthe.run("subscription { cardAdded { id } }", schemas.warm, context: context())

      :ok = Pubsub.subscribe(topic)
      assert_received {:warmed, subscribe_instance}

      for card <- [Card.get(1), Card.get(3)] do
        :ok = Absinthe.Subscription.publish(Pubsub, card, card_added: "cards")
        assert [%{data: %{"cardAdded" => %{"id" => id}}}] = pushes(topic)
        assert id == card.id
      end

      assert_received {:warmed, first}
      assert_received {:warmed, second}
      refute_received {:warmed, _instance}
      assert_received {:publish_actor, %Warden.Actor{instance: ^first}}
      assert_received {:publish_actor, %Warden.Actor{instance: ^second}}
      assert Enum.uniq([subscribe_instance, first, second]) == [subscribe_instance, first, second]
    end
  end

  describe "the option" do
    test "an anonymous function fails compilation" do
      assert_raise CompileError, ~r/`:warm_actor` must be/, fn ->
        compile_schema(
          @body,
          "authorizer: Warden.Test.WarmActor.Authz, warm_actor: fn actor, _context -> actor end"
        )
      end
    end

    test "a function of another arity or another value fails compilation" do
      for value <- ["&Warden.Test.WarmActor.Warm.warm/1", ":warm", "{\"Warm\", :warm}"] do
        assert_raise CompileError, ~r/`:warm_actor` must be/, fn ->
          compile_schema(@body, "authorizer: Warden.Test.WarmActor.Authz, warm_actor: #{value}")
        end
      end
    end
  end
end
