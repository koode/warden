defmodule Warden.RedteamV2Absinthe.AdmissionTest do
  # Attacks on the "admitted values" skip: the pre middleware does not decide the parent
  # object rule again for a value the post middleware admitted under a batched rule.
  # Tests marked HOLE fail while the hole exists; the others document defended attacks.
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers
  import Warden.Test.RedteamV2.People

  alias Warden.Test.RedteamV2.{Card, Schema, Ticket}

  defp tickets(count) do
    for index <- 1..count, do: %Ticket{id: index, workspace_id: "t1", visible: true}
  end

  defp drain_check_many_calls(count) do
    receive do
      {:check_many, :live, _size} -> drain_check_many_calls(count + 1)
    after
      0 -> count
    end
  end

  # HOLE (medium, cost): values that reach an object type through an interface or union
  # are never admitted unless the type also redacts, so every field of every value
  # decides the batched object rule again: one batched call per value and field instead
  # of one per list. With an Ecto policy that is one query per value and field.
  test "a batched object rule over an interface list is not decided again per value and field" do
    entries = tickets(20)
    document = "{ entries { ... on Ticket { id secret workspaceId } } }"

    result = run(Schema, document, abby(), %{entries: entries})

    assert Enum.count(result.data["entries"]) == 20
    calls = drain_check_many_calls(0)

    concrete = run(Schema, "{ tickets { id secret workspaceId } }", abby(), %{entries: entries})
    assert Enum.count(concrete.data["tickets"]) == 20
    concrete_calls = drain_check_many_calls(0)

    assert concrete_calls == 1
    assert calls <= 1, "the interface path made #{calls} batched calls for 20 values"
  end

  # HOLE (medium, cost): the admission lookup hashes {type, actor, parent value} for every
  # field of every object with an object rule, admitted or not. A client that aliases a
  # cheap field many times on an object with a large value makes the server hash that
  # value once per alias; 0.1 decided a role rule in constant time.
  test "selecting a field many times does not cost time proportional to the parent value size" do
    aliases = Enum.map_join(1..300, " ", &"a#{&1}: id")
    document = "{ guardedTicket { #{aliases} } }"
    small = %Ticket{id: 1, blob: "x"}
    large = %Ticket{id: 1, blob: :binary.copy("x", 4_000_000)}

    {small_us, small_result} =
      :timer.tc(fn -> run(Schema, document, abby(), %{ticket: small}) end)

    {large_us, large_result} =
      :timer.tc(fn -> run(Schema, document, abby(), %{ticket: large}) end)

    assert small_result.data["guardedTicket"]["a1"] == 1
    assert large_result.data["guardedTicket"]["a300"] == 1

    assert large_us < small_us * 5 + 150_000,
           "300 aliases took #{div(large_us, 1000)} ms on a 4 MB value, " <>
             "#{div(small_us, 1000)} ms on a small one"
  end

  # Changed to match the decision: an object rule may not read the arguments of the
  # field that returned the value (the client chooses them), so the schema that tried
  # it no longer compiles.
  test "an object rule that reads an argument fails compilation" do
    for rule <- [
          "all_of([tenant_role(:member, tenant: {:arg, [:workspace]}), check(:live)])",
          "any_of([can(Warden.Test.RedteamV2.Cards, :read, arg: [:id]), check(:live)])"
        ] do
      assert_raise CompileError,
                   ~r/ScopedTicket: an object rule cannot read field arguments/,
                   fn ->
                     compile_schema(
                       """
                         object :scoped_ticket do
                           authorize #{rule}
                           field :id, :integer
                         end

                         query do
                           field :scoped_tickets, list_of(:scoped_ticket) do
                             arg :workspace, non_null(:string)
                             arg :id, :integer
                           end
                         end
                       """,
                       "authorizer: Warden.Test.RedteamV2.Authz"
                     )
                   end
    end

    assert_raise CompileError, ~r/`:default_object_rule` is an object rule/, fn ->
      compile_schema(
        """
          query do
            field :ok, :string
          end
        """,
        "authorizer: Warden.Test.RedteamV2.Authz, default_object_rule: tenant_role(:member, tenant: {:arg, [:workspace]})"
      )
    end
  end

  test "an admitted value is decided again under another object type" do
    card = %Card{id: 2, workspace_id: "t1", visible: false, note: "hidden note"}
    document = "{ cards { id note } cardSummaries { id note } }"

    result = run(Schema, document, abby(), %{cards: [card]})

    assert result.data == %{"cards" => [nil], "cardSummaries" => [nil]}
  end

  test "an admitted value is decided again for the same struct with one field changed" do
    visible = %Ticket{id: 1, visible: true, secret: "shown"}
    hidden = %Ticket{visible | visible: false, secret: "not shown"}

    result = run(Schema, "{ tickets { id secret } }", abby(), %{entries: [visible, hidden]})

    assert result.data["tickets"] == [%{"id" => 1, "secret" => "shown"}, nil]
  end

  test "aliases and fragments over one admitted list never widen what is shown" do
    entries = [%Ticket{id: 1, visible: true}, %Ticket{id: 2, visible: false, secret: "nope"}]

    document = """
    { first: tickets { id ...Fields } second: tickets { ... on Ticket { secret } } }
    fragment Fields on Ticket { secret }
    """

    result = run(Schema, document, abby(), %{entries: entries})

    refute inspect(result.data) =~ "nope"
    assert [%{"id" => 1}, nil] = result.data["first"]
    assert [%{"secret" => "ticket secret"}, nil] = result.data["second"]
  end
end
