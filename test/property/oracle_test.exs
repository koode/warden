defmodule Warden.Property.OracleTest do
  @moduledoc """
  Random actors against random documents over `Warden.Test.Prop.Schema`.

  The oracle below is written independently of Warden: it hard-codes, as plain boolean
  functions, what the schema's rules mean, and computes the exact `data` the actor may
  see by walking the generated document over the data graph (field collection, fragment
  type conditions, alias merging). The property asserts that the response equals it, so
  no denied value appears anywhere and every allowed value does.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Warden.Test.Prop.Data

  @runs String.to_integer(System.get_env("WARDEN_PROPERTY_RUNS", "500"))

  ## Oracle: the policy, hand-coded

  defp roles(nil), do: []

  defp roles(actor) do
    if :r1 in actor.roles, do: Enum.uniq([:r2 | actor.roles]), else: actor.roles
  end

  defp perms(nil), do: []

  defp perms(actor) do
    if :r2 in roles(actor), do: Enum.uniq(["p1" | actor.perms]), else: actor.perms
  end

  defp owns?(nil, _entity), do: false
  defp owns?(actor, entity), do: entity.owner == actor.id

  defp object_visible?(:alpha, _entity, actor), do: :r2 in roles(actor)
  defp object_visible?(:beta, entity, actor), do: "p1" in perms(actor) or owns?(actor, entity)
  defp object_visible?(:gamma, _entity, _actor), do: true

  defp field_visible?(:label, _entity, actor), do: :r3 in roles(actor)
  defp field_visible?(:secret_a, _entity, actor), do: "p2" in perms(actor)
  defp field_visible?(:secret_b, _entity, actor), do: :r1 in roles(actor)
  defp field_visible?(:secret_g, entity, actor), do: actor != nil and owns?(actor, entity)
  defp field_visible?(_field, _entity, _actor), do: true

  ## Oracle: expected data

  defp expected(roots, actor, vars) do
    Map.new(roots, fn {:root, key, kind, args, sel} ->
      {key, expect_root(kind, args, sel, actor, vars)}
    end)
  end

  defp expect_root(:things, args, sel, actor, _vars) do
    if match?(%{owner_only: true}, args[:filter]) and actor == nil do
      nil
    else
      Enum.map(Data.all(), &render(&1, :thing, sel, actor))
    end
  end

  defp expect_root(:search, _args, sel, actor, _vars) do
    Enum.map(Data.all(), &render(&1, :any_result, sel, actor))
  end

  defp expect_root(:node, %{id: id}, sel, actor, _vars) do
    entity = if id in Data.ids(), do: Data.entity(id)
    render(entity, :thing, sel, actor)
  end

  defp expect_root(:alpha, %{id: id} = args, sel, actor, vars) do
    reveal =
      case Map.get(args, :reveal) do
        {:var, name} -> Map.fetch!(vars, name)
        other -> other
      end

    if reveal == true and :r3 not in roles(actor) do
      nil
    else
      render(Data.entity(id), :alpha, sel, actor)
    end
  end

  defp render(nil, _static, _sel, _actor), do: nil

  defp render(entity, static, sel, actor) do
    visible =
      object_visible?(entity.kind, entity, actor) and (static != :any_result or actor != nil)

    if visible, do: expect_fields(sel, entity, actor), else: nil
  end

  defp expect_fields(sel, entity, actor) do
    sel
    |> collect(entity.kind)
    |> Map.new(fn {key, name, subsels} ->
      {key, field_value(name, subsels, entity, actor)}
    end)
  end

  defp field_value(:__typename, _, entity, _actor), do: type_name(entity.kind)

  defp field_value(:children, sel, entity, actor),
    do: Enum.map(entity.children, &render(Data.entity(&1), :thing, sel, actor))

  defp field_value(:matrix, sel, entity, actor),
    do:
      Enum.map(entity.matrix, fn row ->
        Enum.map(row, &render(Data.entity(&1), :beta, sel, actor))
      end)

  defp field_value(:parent, sel, entity, actor),
    do: render(Data.entity(entity.parent), :alpha, sel, actor)

  defp field_value(:friends, sel, entity, actor),
    do: Enum.map(entity.friends, &render(Data.entity(&1), :alpha, sel, actor))

  defp field_value(scalar, _, entity, actor) do
    if field_visible?(scalar, entity, actor), do: Map.get(entity, scalar), else: nil
  end

  # GraphQL field collection: fragments apply when their type condition matches the
  # concrete type (or is the Thing interface every object implements); fields with the
  # same response key merge their sub-selections.
  defp collect(sel, concrete) do
    sel
    |> do_collect(concrete)
    |> Enum.reduce({[], %{}}, fn {key, name, sub}, {order, acc} ->
      case acc do
        %{^key => {^name, subs}} -> {order, Map.put(acc, key, {name, subs ++ (sub || [])})}
        _ -> {order ++ [key], Map.put(acc, key, {name, sub || []})}
      end
    end)
    |> then(fn {order, acc} ->
      Enum.map(order, fn key ->
        {name, subs} = acc[key]
        {key, name, subs}
      end)
    end)
  end

  defp do_collect(sel, concrete) do
    Enum.flat_map(sel, fn
      {:field, key, name, sub} ->
        [{key, name, sub}]

      {frag, cond, sub} when frag in [:inline, :spread] ->
        if cond == concrete or cond == :thing, do: do_collect(sub, concrete), else: []
    end)
  end

  defp type_name(:alpha), do: "Alpha"
  defp type_name(:beta), do: "Beta"
  defp type_name(:gamma), do: "Gamma"
  defp type_name(:thing), do: "Thing"

  ## Generators

  @scalars %{
    thing: [:id, :name, :label, :__typename],
    alpha: [:id, :name, :label, :secret_a, :__typename],
    beta: [:id, :name, :label, :secret_b, :__typename],
    gamma: [:id, :name, :label, :secret_g, :__typename],
    any_result: [:__typename]
  }

  @objects %{
    thing: [],
    alpha: [children: :thing, matrix: :beta],
    beta: [parent: :alpha],
    gamma: [friends: :alpha],
    any_result: []
  }

  @conditions %{
    thing: [:alpha, :beta, :gamma, :thing],
    any_result: [:alpha, :beta, :gamma, :thing],
    alpha: [:alpha, :thing],
    beta: [:beta, :thing],
    gamma: [:gamma, :thing]
  }

  # Selections carry a placeholder key; real response keys are assigned at render time.
  defp selection_set(ctx, depth) do
    scalar =
      gen all(name <- member_of(@scalars[ctx]), alias? <- boolean()) do
        {:field, alias?, name, nil}
      end

    object =
      if depth > 0 and @objects[ctx] != [] do
        [
          gen all(
                {name, type} <- member_of(@objects[ctx]),
                alias? <- boolean(),
                sub <- selection_set(type, depth - 1)
              ) do
            {:field, alias?, name, sub}
          end
        ]
      else
        []
      end

    fragment =
      if depth > 0 do
        [
          gen all(
                kind <- member_of([:inline, :spread]),
                cond <- member_of(@conditions[ctx]),
                sub <- selection_set(cond, depth - 1)
              ) do
            {kind, cond, sub}
          end
        ]
      else
        []
      end

    list_of(one_of([scalar | object ++ fragment]), min_length: 1, max_length: 4)
  end

  defp root_field do
    one_of([
      gen all(
            filter <-
              one_of([
                constant(nil),
                map(boolean(), &%{owner_only: &1}),
                constant(%{kind: "x"})
              ]),
            sel <- selection_set(:thing, 3)
          ) do
        {:things, if(filter, do: %{filter: filter}, else: %{}), sel}
      end,
      gen all(sel <- selection_set(:any_result, 3)) do
        {:search, %{}, sel}
      end,
      gen all(id <- member_of(Data.ids() ++ ["zz"]), sel <- selection_set(:thing, 3)) do
        {:node, %{id: id}, sel}
      end,
      gen all(
            id <- member_of(["a1", "a2"]),
            reveal <-
              one_of([constant(:omit), boolean(), map(boolean(), &{:var_value, &1})]),
            sel <- selection_set(:alpha, 3)
          ) do
        args = %{id: id}
        args = if reveal == :omit, do: args, else: Map.put(args, :reveal, reveal)
        {:alpha, args, sel}
      end
    ])
  end

  defp subset(items) do
    map(list_of(boolean(), length: length(items)), fn bits ->
      for {item, true} <- Enum.zip(items, bits), do: item
    end)
  end

  defp non_empty_subset(items), do: filter(subset(items), &(&1 != []))

  defp actor do
    one_of([
      constant(nil),
      gen all(
            id <- member_of(["u1", "u2", "u3"]),
            roles <- subset([:r1, :r2, :r3]),
            perms <- subset(["p1", "p2"])
          ) do
        %{id: id, roles: roles, perms: perms}
      end
    ])
  end

  ## Rendering the document

  defp render_doc(raw_roots) do
    {roots, state} =
      Enum.map_reduce(raw_roots, %{n: 0, frags: [], vars: %{}, var_decls: []}, fn {kind, args,
                                                                                   sel},
                                                                                  st ->
        st = %{st | n: st.n + 1}
        key = "r#{st.n}"

        {args, st} =
          case args do
            %{reveal: {:var_value, value}} ->
              name = "v#{st.n}"

              {%{args | reveal: {:var, name}},
               %{
                 st
                 | vars: Map.put(st.vars, name, value),
                   var_decls: ["$#{name}: Boolean" | st.var_decls]
               }}

            _ ->
              {args, st}
          end

        {sel, st} = keyed(sel, st)
        {{:root, key, kind, args, sel}, st}
      end)

    body =
      Enum.map_join(roots, " ", fn {:root, key, kind, args, sel} ->
        "#{key}: #{camel(kind)}#{render_args(args)} #{render_sel(sel)}"
      end)

    header =
      case state.var_decls do
        [] -> "query"
        decls -> "query(#{Enum.join(Enum.reverse(decls), ", ")})"
      end

    frags =
      Enum.map_join(Enum.reverse(state.frags), "\n", fn {name, cond, sel} ->
        "fragment #{name} on #{type_name(cond)} #{render_sel(sel)}"
      end)

    {"#{header} { #{body} }\n#{frags}", roots, state.vars}
  end

  # Assigns response keys (unique aliases where requested) and fragment names.
  defp keyed(sel, st) do
    Enum.map_reduce(sel, st, fn
      {:field, alias?, name, sub}, st ->
        st = %{st | n: st.n + 1}
        key = if alias?, do: "k#{st.n}", else: camel(name)

        {sub, st} = if sub, do: keyed(sub, st), else: {nil, st}
        {{:field, {key, alias?}, name, sub}, st}

      {:inline, cond, sub}, st ->
        {sub, st} = keyed(sub, st)
        {{:inline, cond, sub}, st}

      {:spread, cond, sub}, st ->
        {sub, st} = keyed(sub, st)
        st = %{st | n: st.n + 1}
        name = "F#{st.n}"
        {{:spread, {cond, name}, sub}, %{st | frags: [{name, cond, sub} | st.frags]}}
    end)
  end

  defp render_sel(sel) do
    inner =
      Enum.map_join(sel, " ", fn
        {:field, {key, true}, name, sub} -> "#{key}: #{camel(name)}#{render_sub(sub)}"
        {:field, {_key, false}, name, sub} -> "#{camel(name)}#{render_sub(sub)}"
        {:inline, cond, sub} -> "... on #{type_name(cond)} #{render_sel(sub)}"
        {:spread, {_cond, name}, _sub} -> "...#{name}"
      end)

    "{ #{inner} }"
  end

  defp render_sub(nil), do: ""
  defp render_sub(sub), do: " " <> render_sel(sub)

  defp render_args(args) when map_size(args) == 0, do: ""

  defp render_args(args) do
    inner =
      args
      |> Enum.sort()
      |> Enum.map_join(", ", fn {k, v} -> "#{camel(k)}: #{render_value(v)}" end)

    "(#{inner})"
  end

  defp render_value({:var, name}), do: "$#{name}"
  defp render_value(v) when is_binary(v), do: inspect(v)
  defp render_value(v) when is_boolean(v), do: to_string(v)

  defp render_value(%{} = m) do
    "{" <>
      Enum.map_join(Enum.sort(m), ", ", fn {k, v} -> "#{camel(k)}: #{render_value(v)}" end) <> "}"
  end

  defp camel(:__typename), do: "__typename"
  defp camel(atom), do: atom |> Atom.to_string() |> Absinthe.Utils.camelize(lower: true)

  # Normalise the keyed selections back to the oracle's shape.
  defp oracle_roots(roots),
    do:
      Enum.map(roots, fn {:root, k, kind, args, sel} ->
        {:root, k, kind, args, oracle_sel(sel)}
      end)

  defp oracle_sel(nil), do: nil

  defp oracle_sel(sel) do
    Enum.map(sel, fn
      {:field, {key, _}, name, sub} -> {:field, key, name, oracle_sel(sub)}
      {:inline, cond, sub} -> {:inline, cond, oracle_sel(sub)}
      {:spread, {cond, _name}, sub} -> {:spread, cond, oracle_sel(sub)}
    end)
  end

  ## Properties

  @tag timeout: :infinity
  property "the response equals the oracle: nothing denied appears, everything allowed does" do
    check all(
            actor <- actor(),
            raw_roots <- list_of(root_field(), min_length: 1, max_length: 3),
            max_runs: @runs
          ) do
      {doc, roots, vars} = render_doc(raw_roots)

      {:ok, result} =
        Absinthe.run(doc, Warden.Test.Prop.Schema, context: %{actor: actor}, variables: vars)

      unless Map.has_key?(result, :data) do
        flunk("document did not validate: #{inspect(result[:errors])}\n#{doc}")
      end

      expected = expected(oracle_roots(roots), actor, vars)

      assert result.data == expected, """
      actor: #{inspect(actor)}
      document: #{doc}
      variables: #{inspect(vars)}
      """

      for error <- Map.get(result, :errors, []) do
        assert error.message == "Forbidden", inspect(error)
      end

      bump(:runs)
      if Map.has_key?(result, :errors), do: bump(:with_denials)
      if String.contains?(doc, "fragment "), do: bump(:named_fragments)
      if String.contains?(doc, "... on "), do: bump(:inline_fragments)
      if String.contains?(doc, "matrix"), do: bump(:nested_lists)
      if String.contains?(doc, "$v"), do: bump(:variables)
    end

    # The generator must actually exercise the interesting cases.
    stats = Process.get(:oracle_stats)
    assert stats.runs >= @runs
    assert stats.with_denials > div(@runs, 4), inspect(stats)

    for key <- [:named_fragments, :inline_fragments, :nested_lists, :variables] do
      assert Map.get(stats, key, 0) > div(@runs, 20), inspect(stats)
    end
  end

  defp bump(key) do
    stats = Process.get(:oracle_stats, %{runs: 0, with_denials: 0})
    Process.put(:oracle_stats, Map.update(stats, key, 1, &(&1 + 1)))
  end

  ## Rule evaluation against an independent evaluator

  defp rule_gen do
    leaf =
      one_of([
        constant(:public),
        constant(:authenticated),
        constant(:deny),
        map(member_of([:r1, :r2, :r3]), &{:role, &1}),
        map(non_empty_subset([:r1, :r2, :r3]), &{:any_role, &1}),
        map(member_of(["p1", "p2"]), &{:permission, &1}),
        map(non_empty_subset(["p1", "p2"]), &{:all_permissions, &1}),
        map(non_empty_subset(["p1", "p2"]), &{:any_permission, &1}),
        constant({:check, :owns, []})
      ])

    tree(leaf, fn child ->
      one_of([
        map(list_of(child, min_length: 1, max_length: 3), &{:all, &1}),
        map(list_of(child, min_length: 1, max_length: 3), &{:any, &1})
      ])
    end)
  end

  defp oracle_eval(:public, _a, _v), do: true
  defp oracle_eval(:deny, _a, _v), do: false
  defp oracle_eval(:authenticated, a, _v), do: a != nil
  defp oracle_eval({:role, r}, a, _v), do: r in roles(a)
  defp oracle_eval({:any_role, rs}, a, _v), do: Enum.any?(rs, &(&1 in roles(a)))
  defp oracle_eval({:permission, p}, a, _v), do: p in perms(a)
  defp oracle_eval({:all_permissions, ps}, a, _v), do: Enum.all?(ps, &(&1 in perms(a)))
  defp oracle_eval({:any_permission, ps}, a, _v), do: Enum.any?(ps, &(&1 in perms(a)))
  defp oracle_eval({:check, :owns, []}, a, v), do: owns?(a, v)
  defp oracle_eval({:all, rs}, a, v), do: Enum.all?(rs, &oracle_eval(&1, a, v))
  defp oracle_eval({:any, rs}, a, v), do: Enum.any?(rs, &oracle_eval(&1, a, v))

  property "Warden.Rule.evaluate agrees with an independent evaluator" do
    check all(
            actor <- actor(),
            rule <- rule_gen(),
            owner <- member_of(["u1", "u2", "u3"]),
            max_runs: @runs
          ) do
      value = %{owner: owner}
      context = %{actor: actor}
      expected = oracle_eval(rule, actor, value)
      result = Warden.authorize(context, rule, authorizer: Warden.Test.Prop.Authz, value: value)
      assert result == :ok == expected, "rule: #{inspect(rule)}, actor: #{inspect(actor)}"
    end
  end
end
