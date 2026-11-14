defmodule Warden.RedteamV2Absinthe.ArgumentsTest do
  # Attacks on `can/3` with `arg:`, `on_deny:` and `covered()`. Tests marked HOLE fail
  # while the hole exists; the others document defended attacks.
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers
  import Warden.Test.RedteamV2.People

  alias Warden.Test.RedteamV2.{Card, Schema}

  @by_ids "query Ids($ids: [Int]) { cardsByIds(ids: $ids) { id } }"

  # HOLE (low/medium): `can(policy, action, arg: path)` documents that "a missing id, an
  # empty list or a nil value denies". A `null` inside a list of ids is passed to the
  # policy as `{schema, nil}` instead, and a policy that reads a nil id as "a new record"
  # grants it. Here the only real id is visible, so the null is the whole attack.
  test "a null id inside a list of ids denies without asking the policy" do
    result = run(Schema, @by_ids, abby(), %{}, %{"ids" => [1, nil]})

    refute_received {:resolver_ran, :cards_by_ids, _args}
    assert result.data == %{"cardsByIds" => nil}
    refute_received {:asked_about, {Card, nil}}
  end

  test "a null, missing or empty list of ids denies before the resolver" do
    for variables <- [%{"ids" => nil}, %{}, %{"ids" => []}] do
      result = run(Schema, @by_ids, abby(), %{}, variables)

      assert result.data == %{"cardsByIds" => nil}
      assert [%{message: "Forbidden"}] = result.errors
    end

    refute_received {:resolver_ran, :cards_by_ids, _args}
    refute_received {:asked_about, _value}
  end

  test "one denied id in a list denies the whole field before the resolver" do
    result = run(Schema, @by_ids, abby(), %{}, %{"ids" => [1, 2]})

    assert result.data == %{"cardsByIds" => nil}
    refute_received {:resolver_ran, :cards_by_ids, _args}
  end

  test "a single id given for a list is coerced and checked" do
    result = run(Schema, @by_ids, abby(), %{}, %{"ids" => 2})

    assert result.data == %{"cardsByIds" => nil}
    refute_received {:resolver_ran, :cards_by_ids, _args}
  end

  test "allowed ids reach the resolver and the object rule still applies to the result" do
    result = run(Schema, @by_ids, abby(), %{}, %{"ids" => [1, 3]})

    assert result.data == %{"cardsByIds" => [%{"id" => 1}, %{"id" => 3}]}
    assert_received {:resolver_ran, :cards_by_ids, %{ids: [1, 3]}}
  end

  test "an arg: path through a list of input objects denies instead of guessing an index" do
    schema =
      compile_schema(
        """
          input_object :card_ref do
            field :id, :integer
          end

          object :card do
            field :id, :integer
          end

          query do
            field :cards, list_of(:card) do
              arg :refs, list_of(:card_ref)
              authorize can(Warden.Test.RedteamV2.Cards, :read, arg: [:refs, :id])
              resolve fn _args, resolution ->
                send(resolution.context.test_pid, :resolver_ran)
                {:ok, []}
              end
            end
          end
        """,
        "authorizer: Warden.Test.RedteamV2.Authz"
      )

    result = run(schema, "{ cards(refs: [{id: 1}]) { id } }", abby())

    assert result.data == %{"cards" => nil}
    refute_received :resolver_ran
  end

  test "on_deny: :null hides only field-rule denials; argument denials keep the error" do
    schema =
      compile_schema(
        """
          query do
            field :report, :string do
              arg :detailed, :boolean, default_value: false
              authorize(role(:staff), on_deny: :null)
              authorize_args detailed: deny()
              resolve fn _args, _resolution -> {:ok, "report"} end
            end
          end
        """,
        "authorizer: Warden.Test.RedteamV2.Authz"
      )

    hidden = run(schema, "{ report }", abby())
    argument_denied = run(schema, "{ report(detailed: true) }", staff())

    assert hidden.data == %{"report" => nil}
    refute Map.has_key?(hidden, :errors)
    assert argument_denied.data == %{"report" => nil}
    assert [%{message: "Forbidden"}] = argument_denied.errors
  end

  test "covered() is refused on a type whose only object rule is public()" do
    assert_raise CompileError, ~r/covered\(\) needs an object rule/, fn ->
      compile_schema(
        """
          object :open do
            authorize public()
            field :id, :integer do
              authorize covered()
            end
          end

          query do
            field :open, :open, resolve: fn _args, _resolution -> {:ok, %{id: 1}} end
          end
        """,
        "authorizer: Warden.Test.RedteamV2.Authz"
      )
    end
  end

  test "covered() through an interface is guarded by the interface rule on implementors" do
    schema =
      compile_schema(
        """
          interface :thing do
            authorize role(:staff)
            field :id, :integer do
              authorize covered()
            end
            resolve_type fn _value, _resolution -> :box end
          end

          object :box do
            interface :thing
            field :id, :integer
          end

          query do
            field :box, :box do
              authorize public()
              resolve fn _args, _resolution -> {:ok, %{id: 1}} end
            end

            field :thing, :thing do
              authorize public()
              resolve fn _args, _resolution -> {:ok, %{id: 1}} end
            end
          end
        """,
        "authorizer: Warden.Test.RedteamV2.Authz, strict_mode: :all"
      )

    assert run(schema, "{ box { id } thing { id } }", abby()).data == %{
             "box" => nil,
             "thing" => nil
           }

    assert run(schema, "{ box { id } }", staff()).data == %{"box" => %{"id" => 1}}
  end
end
