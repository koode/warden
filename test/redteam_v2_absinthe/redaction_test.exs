defmodule Warden.RedteamV2Absinthe.RedactionTest do
  # Attacks on `redact_with`: paths where a child field could read the unredacted value
  # or run under a type whose rules were not decided. Tests marked HOLE fail while the
  # hole exists; the others document defended attacks.
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers
  import Warden.Test.RedteamV2.People

  alias Warden.Test.RedteamV2.{Card, Listing, Schema, Ticket}

  # HOLE (low): `Decide` resolves the concrete type of an abstract value before redaction
  # and decides that type's rules; Absinthe resolves the type again on the redacted value.
  # When the redaction changes what `resolve_type` reads, the value runs as another
  # concrete type whose field rules were never meant for it.
  test "redaction cannot change the concrete type a value runs as" do
    listing = %Listing{id: 1, kind: "secret", code: "launch code"}

    document = """
    { listings { __typename ... on SecretListing { code } ... on PlainListing { code } } }
    """

    result = run(Schema, document, abby(), %{listings: [listing]})

    refute inspect(result.data) =~ "launch code"
  end

  # HOLE (low, hardening): a second object type over a struct that has a registered field
  # policy, linked to it by its `can/2` policy, has no `redact_with` and serves the
  # unredacted struct. `require_can_for` exists for object rules; nothing ties an object
  # type of a redacted struct to its field policy.
  #
  # Changed to match the decision: such a type must declare `redact_with`, else the
  # schema fails compilation; the shared schema's `CardSummary` now declares it.
  test "a second object type over a redacted struct still redacts" do
    result = run(Schema, "{ cardSummaries { id note } }", abby())

    refute inspect(result.data) =~ "note 1"

    assert_raise CompileError,
                 ~r/Bare exposes :note .* add `redact_with Warden.Test.RedteamV2.CardFields`/,
                 fn ->
                   compile_schema(
                     """
                       object :bare do
                         authorize can(Warden.Test.RedteamV2.Cards, :read)
                         field :id, :integer
                         field :note, :string
                       end

                       object :ids_only do
                         authorize can(Warden.Test.RedteamV2.Cards, :read)
                         field :id, :integer
                       end

                       query do
                         field :bare, :bare
                         field :ids_only, :ids_only
                       end
                     """,
                     "authorizer: Warden.Test.RedteamV2.Authz"
                   )
                 end

    # A type that exposes none of the redacted fields needs nothing.
    assert compile_schema(
             """
               object :ids_only do
                 authorize can(Warden.Test.RedteamV2.Cards, :read)
                 field :id, :integer
               end

               query do
                 field :ids_only, :ids_only
               end
             """,
             "authorizer: Warden.Test.RedteamV2.Authz"
           )
  end

  test "an on_deny replacement value is redacted and decided like a resolved value" do
    result = run(Schema, "{ featuredCard { id note } }", abby())

    assert result.data == %{"featuredCard" => %{"id" => 9, "note" => "[hidden]"}}
    refute_received {:resolver_ran, :featured_card}
  end

  test "an interface list mixing redacted and batched types keeps order under redaction" do
    entries = [
      %Ticket{id: 10, visible: true, secret: "t10"},
      Card.get(1),
      %Ticket{id: 11, visible: false, secret: "t11"},
      Card.get(2),
      Card.get(3)
    ]

    document = "{ entries { __typename id ... on Card { note } ... on Ticket { secret } } }"
    result = run(Schema, document, abby(), %{entries: entries})

    assert result.data["entries"] == [
             %{"__typename" => "Ticket", "id" => 10, "secret" => "t10"},
             %{"__typename" => "Card", "id" => 1, "note" => "[hidden]"},
             nil,
             nil,
             %{"__typename" => "Card", "id" => 3, "note" => "[hidden]"}
           ]
  end

  test "staff reads the unredacted value, and the redaction of one actor is not reused" do
    document = "{ cards { id note } }"

    staff_result = run(Schema, document, staff())
    abby_result = run(Schema, document, abby())

    assert [%{"note" => "note 1"}, nil, %{"note" => "note 3"}] = staff_result.data["cards"]
    assert [%{"note" => "[hidden]"}, nil, %{"note" => "[hidden]"}] = abby_result.data["cards"]
  end
end
