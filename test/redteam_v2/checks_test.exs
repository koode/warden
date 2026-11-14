defmodule Warden.RedteamV2.ChecksTest do
  # Security goals 2 and 12: only `true` grants; batches, timeouts and broken callbacks
  # fail closed.
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.RedteamV2.People

  alias Warden.RedteamV2.{Doc, DocPolicy}

  describe "holes" do
    # LOW: a check with `timeout:` runs in a new process that carries only `$callers`.
    # Process-dictionary state the app relies on (a tenant prefix, a dynamic repo) is
    # gone, so the same check answers differently with and without a timeout.
    test "a timed check sees the caller's process state like an untimed one" do
      Process.put(:redteam_scope, :tenant_a)

      assert Warden.allowed?(actor(abby()), check(:dict))
      assert Warden.allowed?(actor(abby()), check(:timed_dict))
    end

    # LOW: a nil id inside an id list reaches the policy as `{schema, nil}`, although
    # a nil value or a missing id denies without asking.
    test "a nil id inside an argument list is denied without asking the policy" do
      docs = %{1 => %Doc{id: 1, workspace_id: "a", owner_id: "abby"}}
      context = context(abby(), %{docs: docs})

      refute Warden.allowed?(actor(abby()), can(DocPolicy, :write, arg: [:ids]),
               args: %{ids: [1, nil]},
               context: context
             )

      refute_received {:allowed?, :write, {Doc, nil}}
    end
  end

  describe "defended" do
    test "only true grants, from check/2, check_many/2 and policies alike" do
      context = context(abby(), %{note_many: fn notes -> Enum.map(notes, fn _note -> 1 end) end})
      note = %Warden.RedteamV2.Note{id: 1, workspace_id: "a"}

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(actor(abby()), can(Warden.RedteamV2.NotePolicy, :read),
          value: note,
          context: context
        )
      end

      many_ok =
        context(abby(), %{note_many: fn notes -> Enum.map(notes, fn _note -> :ok end) end})

      assert_raise Warden.PolicyError, fn ->
        Warden.filter(actor(abby()), can(Warden.RedteamV2.NotePolicy, :read), [note, note],
          context: many_ok
        )
      end
    end

    test "a timed-out check never grants, inside any_of too" do
      context = context(abby(), %{sleep: 50})

      refute Warden.allowed?(actor(abby()), check(:timed_racy), context: context)

      refute Warden.allowed?(actor(abby()), any_of([deny(), check(:timed_racy)]),
               context: context
             )

      {:error, denial} = Warden.authorize(actor(abby()), check(:timed_racy), context: context)
      assert denial.reason == :unavailable
    end

    test "check options are validated in the core API" do
      typed = Warden.Test.V2.Authz
      user = %{current_user: Warden.Test.V2.People.abby()}

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(user, check(:typed, role: "owner"), authorizer: typed)
      end

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(user, check(:typed, role: :guest), authorizer: typed)
      end

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(user, check(:typed, role: :owner, extra: 1), authorizer: typed)
      end

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(user, check(:typed), authorizer: typed)
      end

      assert Warden.allowed?(user, check(:typed, role: :owner), authorizer: typed)
    end

    test "a policy of another authorizer and an action it lacks are refused" do
      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(actor(abby()), can(Warden.Test.V2.Docs, :read), value: nil)
      end

      assert_raise Warden.PolicyError, fn ->
        Warden.allowed?(actor(abby()), can(DocPolicy, :delete), value: nil)
      end
    end

    test "a system actor is refused before any check or policy is called" do
      job = Warden.system_actor(Warden.RedteamV2.Authz, kind: :agent)
      doc = %Doc{id: 1, workspace_id: "a", owner_id: "abby", public: true}
      context = context(nil)

      for rule <- [
            authenticated(),
            role(:staff),
            permission("docs:read"),
            tenant_role(:member),
            check(:owner),
            check(:hooked),
            check(:visible_many),
            session(),
            credential_scope("docs:read"),
            can(DocPolicy, :read)
          ] do
        refute Warden.allowed?(job, rule, value: doc, context: context)
        assert Warden.filter(job, rule, [doc], context: context) == []
        assert Warden.explain(job, rule, value: doc, context: context).result == :deny
      end

      refute_received {:check, _name, _tenant}
      refute_received {:check_many, _name, _tenants}
      refute_received {:allowed?, _action, _value}
    end
  end
end
