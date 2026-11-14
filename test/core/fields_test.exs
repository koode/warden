defmodule Warden.FieldsTest do
  use ExUnit.Case, async: true

  import Warden.Test.Fields.People

  alias Warden.Fields.Redactor
  alias Warden.Test.Decisions
  alias Warden.Test.Fields.{Authz, Comment, Issue, Tag, UserCard}

  @trashed ~U[2026-11-01 10:00:00Z]

  defp comment(id, extra \\ []) do
    struct!(
      %Comment{
        id: id,
        workspace_id: "t1",
        author_id: "abby",
        body: "body #{id}",
        anchor: "a#{id}"
      },
      extra
    )
  end

  defp drain(acc \\ []) do
    receive do
      {:check_many, _name, _count} = message -> drain([message | acc])
      {:check, _name} = message -> drain([message | acc])
      {:tenant_roles, _user, _tenant} = message -> drain([message | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "redact/3 on one struct" do
    test "a trashed comment's body and anchor are blank for everyone, its author included" do
      trashed = comment(1, trashed_at: @trashed)

      for user <- [abby(), sam(), olivia(), staff()] do
        redacted = Warden.redact(actor(user), trashed)
        assert redacted.body == ""
        assert redacted.anchor == nil
      end
    end

    test "a live comment keeps its body; the author id follows the author and the tenant" do
      live = comment(1)

      assert Warden.redact(actor(abby()), live) == live
      assert Warden.redact(actor(sam()), live) == live
      assert Warden.redact(actor(olivia()), live) == %{live | author_id: nil}
      assert Warden.redact(actor(staff()), live) == %{live | author_id: nil}
    end

    test "tenant-role rules use the value's tenant" do
      card = %UserCard{id: 1, tenant_id: "t1", timezone: "Europe/Amsterdam", email: "e"}

      assert Warden.redact(actor(sam()), card).timezone == "Europe/Amsterdam"
      assert Warden.redact(actor(olivia()), card).timezone == nil
      # Abby owns t1 but is only a guest in t2.
      assert Warden.redact(actor(abby()), card).timezone == "Europe/Amsterdam"
      assert Warden.redact(actor(abby()), %{card | tenant_id: "t2"}).timezone == nil
      assert Warden.redact(actor(abby()), %{card | tenant_id: nil}).timezone == nil
    end

    test "a context map builds the actor; the authorizer comes from the option" do
      redacted = Warden.redact(context(olivia()), comment(1), authorizer: Authz)
      assert redacted.author_id == nil
    end

    test "values without a field policy are returned as they are" do
      tag = %Tag{label: "x"}
      assert Warden.redact(actor(abby()), tag) == tag
      assert Warden.redact(actor(abby()), %{body: "map"}) == %{body: "map"}
      assert Warden.redact(actor(abby()), "text") == "text"
      assert Warden.redact(actor(abby()), nil) == nil
    end
  end

  describe "system actors and delegation" do
    test "a system actor of a kind the rule does not name sees redacted values" do
      chat = Warden.system_actor(Authz, kind: :chat, tenant: "t1")
      redacted = Warden.redact(chat, comment(1))
      assert redacted.body == ""
      assert redacted.anchor == nil
      assert redacted.author_id == nil
    end

    test "a system actor of a kind the check names reaches the check" do
      webhook = Warden.system_actor(Authz, kind: :webhook, tenant: "t1")
      redacted = Warden.redact(webhook, comment(1))
      assert redacted.body == "body 1"
      # No tenant role and no author: the author id stays hidden.
      assert redacted.author_id == nil
      assert Warden.redact(webhook, comment(2, trashed_at: @trashed)).body == ""
    end

    test "a delegated actor keeps a field only when both actors pass its rule" do
      agent = actor(%{id: "agent", kind: :agent, memberships: %{"t1" => [:member]}})
      member = actor(sam())
      guest = actor(olivia())

      assert Warden.redact(Warden.on_behalf_of(agent, member), comment(1)).author_id == "abby"
      assert Warden.redact(Warden.on_behalf_of(agent, guest), comment(1)).author_id == nil
    end
  end

  describe "redact/3 on lists" do
    test "every rule runs once per list: a batched check is called once, order is kept" do
      comments = [comment(1), comment(2, trashed_at: @trashed), comment(3)]
      drain()

      redacted = Warden.redact(context(olivia()), comments, authorizer: Authz)

      assert Enum.map(redacted, & &1.id) == [1, 2, 3]
      assert Enum.map(redacted, & &1.body) == ["body 1", "", "body 3"]
      messages = drain()
      assert Enum.count(messages, &match?({:check_many, :live, 3}, &1)) == 1
      assert Enum.count(messages, &match?({:check_many, _name, _count}, &1)) == 1
      # Tenant roles are read once for the whole list, not per comment.
      assert Enum.count(messages, &match?({:tenant_roles, "olivia", "t1"}, &1)) == 1
    end

    test "unregistered values in a list are left alone" do
      tag = %Tag{label: "x"}
      list = [tag, comment(1, trashed_at: @trashed), "text", nil, comment(2)]

      assert [^tag, %Comment{body: ""}, "text", nil, %Comment{body: "body 2"}] =
               Warden.redact(actor(abby()), list)
    end

    test "structs of several policies in one list are each decided once per rule" do
      card = %UserCard{id: 1, tenant_id: "t1", timezone: "UTC", email: "e"}
      list = [comment(1), card, comment(2, trashed_at: @trashed), card]
      drain()

      assert [%Comment{body: "body 1"}, %UserCard{email: nil}, %Comment{body: ""}, %UserCard{}] =
               Warden.redact(context(sam()), list, authorizer: Authz)

      assert [{:check_many, :live, 2}] =
               for({:check_many, _name, _count} = message <- drain(), do: message)
    end

    test "without deep:, nested structs are not redacted" do
      issue = %Issue{
        id: 1,
        tenant_id: "t1",
        title: "T",
        comments: [comment(1, trashed_at: @trashed)]
      }

      redacted = Warden.redact(actor(abby()), issue)
      assert hd(redacted.comments).body == "body 1"
    end
  end

  describe "redact/3 with deep: true" do
    test "redacts nested registered structs, leaves others alone and keeps list order" do
      not_loaded = %Ecto.Association.NotLoaded{__field__: :cards, __owner__: Issue}
      inner = comment(9, trashed_at: @trashed)
      tag = %Tag{label: "keep", body: inner}

      issue = %Issue{
        id: 1,
        tenant_id: "t2",
        title: "Plan",
        tag: tag,
        comments: [comment(1), comment(2, trashed_at: @trashed), comment(3)],
        cards: not_loaded
      }

      payload = %{issue: issue, extra: [{:comment, comment(4, trashed_at: @trashed)}], count: 3}

      redacted = Warden.redact(actor(sam()), payload, deep: true)

      # Sam is not in t2: the issue title is redacted; in t1 it is not.
      assert redacted.issue.title == "[private]"
      assert Warden.redact(actor(sam()), %{issue | tenant_id: "t1"}).title == "Plan"
      assert Enum.map(redacted.issue.comments, & &1.id) == [1, 2, 3]
      assert Enum.map(redacted.issue.comments, & &1.body) == ["body 1", "", "body 3"]
      assert [{:comment, %Comment{body: ""}}] = redacted.extra
      assert redacted.count == 3
      # Unregistered structs are left alone with their contents.
      assert redacted.issue.tag == tag
      assert redacted.issue.cards == not_loaded
    end

    test "each level of nesting is one batch per rule" do
      issues =
        for id <- 1..3 do
          %Issue{
            id: id,
            tenant_id: "t1",
            title: "T",
            comments: [comment(id * 10), comment(id * 10 + 1)]
          }
        end

      drain()
      redacted = Warden.redact(context(abby()), issues, deep: true, authorizer: Authz)
      assert [_first, _second, _third] = redacted

      assert [{:check_many, :live, 6}] =
               for({:check_many, _name, _count} = message <- drain(), do: message)
    end

    test "a field the outer policy replaced is not walked into" do
      issue = %Issue{id: 1, tenant_id: "t9", title: %{nested: comment(1)}}
      drain()
      redacted = Warden.redact(context(abby()), issue, deep: true, authorizer: Authz)
      assert redacted.title == "[private]"
      assert for({:check_many, _name, _count} = message <- drain(), do: message) == []
    end

    test "improper lists and tuples are walked" do
      value = [comment(1, trashed_at: @trashed) | {:tail, comment(2, trashed_at: @trashed)}]
      [first | {:tail, second}] = Warden.redact(actor(abby()), value, deep: true)
      assert first.body == ""
      assert second.body == ""
    end
  end

  describe "visible_fields/3" do
    test "returns the fields left as they are" do
      all = MapSet.new([:id, :workspace_id, :author_id, :trashed_at, :body, :anchor, :hidden])

      assert Warden.visible_fields(actor(abby()), comment(1)) == all

      assert Warden.visible_fields(actor(olivia()), comment(1, trashed_at: @trashed)) ==
               MapSet.difference(all, MapSet.new([:body, :anchor, :author_id]))
    end

    test "a field whose value equals the replacement still counts as redacted" do
      refute :body in Warden.visible_fields(
               actor(abby()),
               comment(1, body: "", trashed_at: @trashed)
             )
    end

    test "a struct without a field policy shows every field; a non-struct raises" do
      assert Warden.visible_fields(actor(abby()), %Tag{}) == MapSet.new([:label, :body])
      assert_raise ArgumentError, fn -> Warden.visible_fields(actor(abby()), %{body: "x"}) end
    end
  end

  describe "telemetry and inspect" do
    test "one event per rule and list, layer :fields, without values" do
      Decisions.attach()
      secret = "the secret body"
      comments = [comment(1, body: secret, trashed_at: @trashed), comment(2, body: secret)]

      _redacted = Warden.redact(context(olivia()), comments, authorizer: Authz)

      events = collect_events()
      assert [_first, _second] = events
      assert Enum.all?(events, fn {_measurements, metadata} -> metadata.layer == :fields end)
      assert Enum.all?(events, fn {_measurements, metadata} -> metadata.kind == :field end)

      assert Enum.sort(Enum.map(events, fn {measurements, _metadata} -> measurements end)) ==
               Enum.sort([%{count: 2, denied: 1}, %{count: 2, denied: 2}])

      refute inspect(events) =~ secret
      refute inspect(events) =~ "abby"
    end

    test "errors about a value never show it" do
      secret = "the secret body"
      value = %{__struct__: Tag, label: secret, body: secret}

      error =
        assert_raise Warden.PolicyError, fn ->
          Redactor.redact_group(
            Warden.Test.Fields.CommentFields,
            [value],
            actor(abby()),
            %{},
            Authz
          )
        end

      refute Exception.message(error) =~ secret
      assert Exception.message(error) =~ "was given a value of another type"
    end

    test "a field policy of another authorizer is refused" do
      assert_raise Warden.PolicyError, ~r/belongs to Warden.Test.Fields.Authz/, fn ->
        Redactor.redact_group(
          Warden.Test.Fields.CommentFields,
          [comment(1)],
          Warden.actor(%{current_user: abby()}, authorizer: Warden.Test.Fields.DupAuthz),
          %{},
          Warden.Test.Fields.DupAuthz
        )
      end
    end

    test "two field policies for one struct are refused" do
      actor = Warden.actor(%{current_user: abby()}, authorizer: Warden.Test.Fields.DupAuthz)

      assert_raise Warden.PolicyError,
                   ~r/two field policies for Warden.Test.Fields.Comment/,
                   fn ->
                     Warden.redact(actor, comment(1))
                   end
    end
  end

  test "redaction returns new values and leaves the input as it was" do
    original = comment(1, trashed_at: @trashed)
    copy = original
    _redacted = Warden.redact(actor(abby()), [original], deep: true)
    assert original == copy
    assert original.body == "body 1"
  end

  defp collect_events(acc \\ []) do
    receive do
      {:decision, measurements, metadata} -> collect_events([{measurements, metadata} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
