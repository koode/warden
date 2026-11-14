defmodule Warden.RedteamV2Ecto.CallbacksTest do
  # Red-team of goal 12 (fail closed) for Warden.Ecto callbacks that need no database.
  use ExUnit.Case, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.RedteamV2Ecto.People
  alias Warden.Test.Ecto.{Issue, Note, Team}

  @authorizer Warden.RedteamV2Ecto.Authz

  describe "HOLE goal 12: a hand-written allowed_many/4 with a wrong length" do
    test "an answer list longer than the structs raises instead of being cut" do
      note = %Note{id: 1, workspace_id: "t1", author_id: "sam"}
      context = People.context(People.sam(), %{extra_answers: [true]})

      assert_raise Warden.PolicyError, fn ->
        WardenEcto.filter(context, :read, [note], authorizer: @authorizer)
      end
    end
  end

  describe "held: fail closed" do
    test "dataloader_query/2 without an actor raises" do
      assert_raise Warden.PolicyError, fn -> WardenEcto.dataloader_query(Team, %{}) end

      assert_raise Warden.PolicyError, fn ->
        WardenEcto.dataloader_query(Team, %{warden_action: :read})
      end
    end

    test "bounds that are not a list raise" do
      credential = %Warden.Credential{method: :api_key, bounds: %{team_ids: MapSet.new([1])}}
      agent = People.actor(People.olivia(), %{credential: credential})

      assert_raise Warden.PolicyError, fn -> WardenEcto.scope(Issue, agent, :read) end
    end

    test "an unknown action and a schema without a policy raise" do
      sam = People.actor(People.sam())

      assert_raise Warden.PolicyError, fn -> WardenEcto.scope(Issue, sam, :write) end

      assert_raise Warden.PolicyError, fn ->
        WardenEcto.scope(Warden.Test.Ecto.Project, sam, :read)
      end
    end

    test "a nil value, another schema's struct and a system actor of another kind deny" do
      sam = People.actor(People.sam())
      hook = Warden.system_actor(@authorizer, kind: :webhook, tenant: "t1")
      rule = Warden.Rule.can(Warden.RedteamV2Ecto.Comments, :read)
      team = %Team{id: 1, workspace_id: "t1"}
      comment = %Warden.Test.Ecto.Comment{id: 1, workspace_id: "t1", author_id: "sam"}

      refute Warden.allowed?(sam, rule, value: nil)
      refute Warden.allowed?(sam, rule, value: team)
      assert Warden.allowed?(sam, rule, value: comment)
      refute Warden.allowed?(hook, rule, value: comment)
    end
  end
end
