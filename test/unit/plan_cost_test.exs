defmodule Warden.PlanCostTest do
  @moduledoc """
  Compile-time guard: `Warden.Absinthe.Plan.build/2` runs on every schema compile, so its cost must
  grow about linearly with the schema. Compares 250 against 2,000 object types (8x the
  work); linear growth gives a ratio near 8, quadratic growth near 64.
  """
  use ExUnit.Case, async: false

  alias Absinthe.Type

  @ratio_bound 24
  @fields_per_object 15

  test "plan building grows linearly with the number of types" do
    config = Warden.Absinthe.Config.config!(Warden.Test.Schema)

    small = best_of(5, fn -> Warden.Absinthe.Plan.build(types(250), config) end)
    large = best_of(5, fn -> Warden.Absinthe.Plan.build(types(2_000), config) end)

    assert large / max(small, 1) < @ratio_bound,
           "8x the types took #{Float.round(large / max(small, 1), 1)}x the time " <>
             "(#{small} µs -> #{large} µs)"
  end

  test "the synthetic schema is planned (the benchmark measures real work)" do
    config = Warden.Absinthe.Config.config!(Warden.Test.Schema)
    plan = Warden.Absinthe.Plan.build(types(10), config)

    assert plan.errors == []
    assert map_size(plan.object_rules) == 10
    # Every field of a ruled object gets a pre check, and every field returning an object
    # gets a post check.
    assert {pre, post} = plan.fields[{:obj1, :next}]
    assert pre != nil and post != nil
  end

  defp best_of(n, fun) do
    Enum.min(for _ <- 1..n, do: elem(:timer.tc(fun), 0))
  end

  # `n` object types, each with an object rule, a link to the next type, and scalar fields
  # of which every third carries a field rule.
  defp types(n) do
    objects =
      for i <- 1..n, into: %{} do
        ident = :"obj#{i}"

        scalars =
          for f <- 1..@fields_per_object, into: %{} do
            rule = if rem(f, 3) == 0, do: [warden_rule: {:role, :admin}], else: []
            {:"f#{f}", field(:"f#{f}", :string, rule)}
          end

        fields = Map.put(scalars, :next, field(:next, :"obj#{rem(i, n) + 1}", []))

        {ident,
         %Type.Object{
           identifier: ident,
           name: "Obj#{i}",
           fields: fields,
           __private__: [meta: [warden_rule: :authenticated]]
         }}
      end

    root_fields = %{first: field(:first, :obj1, [])}

    Map.put(objects, :query, %Type.Object{
      identifier: :query,
      name: "RootQueryType",
      fields: root_fields
    })
  end

  defp field(ident, type, meta) do
    %Type.Field{
      identifier: ident,
      name: Atom.to_string(ident),
      type: type,
      args: %{},
      __private__: [meta: meta]
    }
  end
end
