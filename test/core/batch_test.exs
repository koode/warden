defmodule Warden.BatchTest do
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.V2.People

  alias Warden.Test.V2.Authz

  @docs for index <- 1..6, do: %{id: index, visible: rem(index, 2) == 0, tenant_id: "t1"}

  defp filter(rule, values, extra \\ %{}),
    do: Warden.filter(context(abby(), extra), rule, values, authorizer: Authz)

  defp batch_calls do
    receive do
      {:check_many, name, count} -> [{name, count} | batch_calls()]
    after
      0 -> []
    end
  end

  test "a list calls check_many/2 once, and the result keeps the order" do
    assert Enum.map(filter(check(:visible), @docs), & &1.id) == [2, 4, 6]
    assert batch_calls() == [{:visible, 6}]
  end

  test "inside all_of and any_of every batched check is asked once for the whole list" do
    rule = any_of([all_of([check(:visible), tenant_role(:guest)]), check(:configured_many)])
    many_result = fn checks -> Enum.map(checks, &(&1.value.id == 1)) end
    assert Enum.map(filter(rule, @docs, %{many_result: many_result}), & &1.id) == [1, 2, 4, 6]
    assert Enum.sort(batch_calls()) == [{:configured_many, 6}, {:visible, 6}]
  end

  test "unbatched checks still short-circuit per value" do
    rule = any_of([check(:visible), check(:plain)])
    filter(rule, @docs, %{plain: false})
    checks = for {:check, :plain} <- Process.info(self(), :messages) |> elem(1), do: :plain
    assert checks == [:plain, :plain, :plain]
  end

  test "a single value goes to check/2 when it handles the name, else to check_many/2" do
    context = context(abby())
    refute Warden.allowed?(context, check(:visible), authorizer: Authz, value: %{visible: false})
    assert batch_calls() == [{:visible, 1}]

    assert Warden.allowed?(context, check(:single_or_many), authorizer: Authz)
    assert batch_calls() == []
    assert_received {:check, :single_or_many}
  end

  test "check_many/2 receives each value's check with the rule options" do
    test_pid = self()

    many_result = fn checks ->
      send(test_pid, {:checks, Enum.map(checks, &{&1.name, &1.opts, &1.value.id})})
      Enum.map(checks, fn _check -> true end)
    end

    filter(check(:configured_many, mode: :strict), Enum.take(@docs, 2), %{
      many_result: many_result
    })

    assert_received {:checks,
                     [
                       {:configured_many, [mode: :strict], 1},
                       {:configured_many, [mode: :strict], 2}
                     ]}
  end

  describe "fails closed" do
    for {label, result} <- [
          {"a wrong length",
           quote(do: fn checks -> tl(checks) |> Enum.map(fn _check -> true end) end)},
          {"a longer list",
           quote(do: fn checks -> Enum.map([nil | checks], fn _check -> true end) end)},
          {"a bad element", quote(do: fn checks -> Enum.map(checks, fn _check -> :ok end) end)},
          {"not a list", quote(do: fn _checks -> true end)},
          {"a raise", quote(do: fn _checks -> raise "boom" end)},
          {"an exit", quote(do: fn _checks -> exit(:boom) end)},
          {"a bad reason",
           quote(do: fn checks -> Enum.map(checks, fn _check -> {:deny, "text"} end) end)}
        ] do
      test "on #{label}, also inside any_of" do
        many_result = unquote(result)

        for rule <- [check(:configured_many), any_of([deny(), check(:configured_many)])] do
          assert_raise Warden.PolicyError, fn ->
            filter(rule, @docs, %{many_result: many_result})
          end
        end
      end
    end

    test "{:deny, reason} denies the value with its reason" do
      many_result = fn checks ->
        Enum.map(checks, fn check -> if check.value.id == 1, do: true, else: {:deny, :hidden} end)
      end

      assert [%{id: 1}] = filter(check(:configured_many), @docs, %{many_result: many_result})
    end

    test "a timeout denies every value with :unavailable and never grants" do
      assert filter(check(:slow_many), @docs, %{sleep: 600}) == []
      assert filter(any_of([deny(), check(:slow_many)]), @docs, %{sleep: 600}) == []
      assert filter(check(:slow_many), @docs, %{sleep: 0}) == @docs

      context = context(abby(), %{sleep: 600})

      assert {:error, denial} =
               Warden.authorize(context, check(:slow_many), authorizer: Authz, value: hd(@docs))

      assert denial.reason == :unavailable
    end

    test "a timed-out batch leaves no late message behind" do
      filter(check(:slow_many), @docs, %{sleep: 600})
      Process.sleep(700)
      refute_received {_ref, {:ok, _late}}
    end
  end

  describe "delegated actors" do
    test "the delegator is asked only about the values the actor passed" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(sam()))
      docs = [%{id: 1, tenant_id: "t1", visible: true}, %{id: 2, tenant_id: "t2", visible: true}]
      context = context(nil)

      assert [%{id: 1}] =
               Warden.filter(delegated, all_of([tenant_role(:guest), check(:visible)]), docs,
                 context: context
               )

      assert batch_calls() == [{:visible, 2}, {:visible, 1}]
    end

    test "filter agrees with allowed? value by value" do
      delegated = Warden.on_behalf_of(actor(olivia()), actor(abby()))

      docs =
        for tenant <- ["t1", "t2", "t3"],
            visible <- [true, false],
            do: %{tenant_id: tenant, visible: visible}

      rule = any_of([all_of([tenant_role(:member), check(:visible)]), tenant_role(:guest)])

      expected =
        Enum.filter(docs, &Warden.allowed?(delegated, rule, value: &1, context: context(nil)))

      assert Warden.filter(delegated, rule, docs, context: context(nil)) == expected
    end
  end
end
