defmodule Warden.RedteamV2.RedactionTest do
  # Warden.redact/3 outside GraphQL: what slips through unredacted.
  use ExUnit.Case, async: true

  import Warden.RedteamV2.People

  alias Warden.RedteamV2.{Comment, Thread}
  alias Warden.Test.Decisions

  @secret "comment-body-secret"

  defp foreign_comment(id),
    do: %Comment{id: id, workspace_id: "a", owner_id: "sam", body: @secret}

  describe "holes: deep: true misses registered structs" do
    # DESIGN LIMIT (documented, but contradicts "registered structs at any depth"): a
    # registered struct inside a struct without a field policy is never reached, so a
    # preloaded association of an unregistered parent (an Ecto schema, a MapSet) keeps
    # every redacted field.
    test "a registered struct inside an unregistered struct is redacted" do
      thread = %Thread{id: 1, comments: [foreign_comment(1)]}

      redacted = Warden.redact(actor(abby()), thread, deep: true)

      refute inspect(redacted) =~ @secret
    end

    test "a registered struct inside a MapSet is redacted" do
      payload = %{comments: MapSet.new([foreign_comment(1)])}

      redacted = Warden.redact(actor(abby()), payload, deep: true)

      refute inspect(redacted) =~ @secret
    end

    # LOW: map keys are not walked.
    test "a registered struct used as a map key is redacted" do
      payload = %{foreign_comment(1) => :seen}

      redacted = Warden.redact(actor(abby()), payload, deep: true)

      refute inspect(redacted) =~ @secret
    end
  end

  describe "defended" do
    test "maps, lists, improper lists, tuples and keyword lists are walked, order kept" do
      own = %Comment{id: 2, workspace_id: "a", owner_id: "abby", body: "mine"}

      payload = %{
        list: [foreign_comment(1), own],
        tuple: {:ok, foreign_comment(3)},
        improper: [own | foreign_comment(4)],
        keyword: [first: foreign_comment(5)],
        nested: %{deeper: [{foreign_comment(6)}]},
        not_loaded: %Ecto.Association.NotLoaded{__field__: :comments}
      }

      redacted = Warden.redact(actor(abby()), payload, deep: true)

      refute inspect(redacted) =~ @secret
      assert [%Comment{body: "[hidden]"}, %Comment{body: "mine"}] = redacted.list
      assert [%Comment{body: "mine"} | %Comment{body: "[hidden]"}] = redacted.improper
      assert redacted.not_loaded == payload.not_loaded
    end

    test "a shallow list redacts its registered structs and leaves the rest" do
      values = [foreign_comment(1), :marker, %{body: @secret}]

      assert [%Comment{body: "[hidden]"}, :marker, %{body: @secret}] =
               Warden.redact(actor(abby()), values)
    end

    test "a system actor and an anonymous context see redacted values" do
      webhook = Warden.system_actor(Warden.RedteamV2.Authz, kind: :webhook)

      assert %Comment{body: "[hidden]"} = Warden.redact(webhook, foreign_comment(1))

      assert %Comment{body: "[hidden]"} =
               Warden.redact(%{}, foreign_comment(1), authorizer: Warden.RedteamV2.Authz)
    end

    test "telemetry and check inspect output never show the redacted value" do
      Decisions.attach()

      Warden.redact(actor(abby()), [foreign_comment(1)], context: context(abby()))

      assert_received {:decision, _measurements, metadata}
      assert metadata.layer == :fields
      refute inspect(metadata) =~ @secret
    end

    test "visible_fields/3 agrees with redact/3" do
      fields = Warden.visible_fields(actor(abby()), foreign_comment(1))

      refute MapSet.member?(fields, :body)

      assert MapSet.member?(
               Warden.visible_fields(actor(sam()), foreign_comment(1)),
               :body
             )
    end
  end
end
