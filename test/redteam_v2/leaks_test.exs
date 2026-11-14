defmodule Warden.RedteamV2.LeaksTest do
  # Security goal 13 and the 0.1 inspect guarantee: reasons, traces, errors and
  # telemetry never carry a subject or a guarded value.
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.RedteamV2.People

  alias Warden.RedteamV2.{Doc, Note, NotePolicy}
  alias Warden.Test.Decisions

  @secret "note-body-secret"
  @notes [
    %Note{id: 1, workspace_id: "a", body: @secret},
    %Note{id: 2, workspace_id: "a", body: @secret}
  ]

  defp note_context(extra), do: context(abby(), extra)

  describe "holes: PolicyError messages print what a broken policy returned" do
    # HOLE: allowed_many/4 written as Enum.filter/2 (a likely bug) returns the guarded
    # values; the PolicyError message (logged, in crash reports) prints them.
    test "a wrong-length allowed_many/4 answer is not printed" do
      context = note_context(%{note_many: fn notes -> Enum.filter(notes, &(&1.id == 1)) end})

      error =
        assert_raise Warden.PolicyError, fn ->
          Warden.filter(actor(abby()), can(NotePolicy, :read), @notes, context: context)
        end

      refute Exception.message(error) =~ @secret
    end

    # HOLE: an answer that is the record a policy looked up (truthy, not `true`).
    test "a non-boolean policy answer is not printed" do
      context = note_context(%{note_many: fn notes -> notes end})

      error =
        assert_raise Warden.PolicyError, fn ->
          Warden.allowed?(actor(abby()), can(NotePolicy, :read),
            value: hd(@notes),
            context: context
          )
        end

      refute Exception.message(error) =~ @secret
    end

    # HOLE: Warden.explain/3 is meant for audit logs, but %Warden.Explanation{} has no
    # Inspect of its own, so the details map of a `{:deny, {atom, map}}` reason (which
    # Warden.Denial's inspect drops on purpose) is printed with it.
    test "inspect of an explanation leaves out reason details, like Warden.Denial" do
      doc = %Doc{id: 1, workspace_id: "a", owner_id: "sam", body: @secret}
      explanation = Warden.explain(actor(abby()), check(:reasoned), value: doc)

      assert explanation.result == :deny
      refute inspect(explanation) =~ @secret
    end
  end

  describe "defended" do
    test "denials, ForbiddenError and telemetry keep reason details and values out" do
      Decisions.attach()
      doc = %Doc{id: 1, workspace_id: "a", owner_id: "sam", body: @secret}
      rule = any_of([check(:reasoned), all_of([tenant_role(:owner), check(:reasoned)])])

      {:error, denial} = Warden.authorize(actor(abby()), rule, value: doc)
      refute inspect(denial) =~ @secret
      refute inspect(denial) =~ "abby"

      error =
        assert_raise Warden.ForbiddenError, fn ->
          Warden.authorize!(actor(abby()), rule, value: doc)
        end

      refute inspect(error) =~ @secret
      refute Exception.message(error) =~ @secret

      assert_received {:decision, _measurements, metadata}
      refute inspect(metadata) =~ @secret
      assert metadata.reason == [:not_owner, :not_owner]
    end

    test "explain/3 and authorize/3 agree on the rules of this suite" do
      doc = %Doc{id: 1, workspace_id: "a", owner_id: "abby"}
      other = %Doc{id: 2, workspace_id: "b", owner_id: "sam"}

      rules = [
        check(:owner),
        any_of([check(:reasoned), check(:owner)]),
        all_of([tenant_role(:member), check(:owner)]),
        all_of([tenant_role(:owner), any_of([deny(), check(:visible_many)])]),
        can(Warden.RedteamV2.DocPolicy, :read)
      ]

      for user <- [abby(), sam(), olivia()], rule <- rules, value <- [doc, other, nil] do
        explained = Warden.explain(actor(user), rule, value: value).result
        authorized = if Warden.allowed?(actor(user), rule, value: value), do: :ok, else: :deny
        assert explained == authorized
      end
    end
  end
end
