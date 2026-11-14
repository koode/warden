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

  # The 0.2 rule terms over `Warden.Test.V2.Authz`: kinds, credentials, tenant roles,
  # system and delegated actors, a batched check and a policy. The oracle below restates
  # their meaning as plain functions over the generated actor specs.

  @v2_tenants ["t1", "t2"]
  @v2_tenant_ranks %{owner: 4, admin: 3, member: 2, guest: 1}

  defp v2_user_spec do
    gen all(
          id <- member_of(["abby", "sam", "olivia"]),
          kind <- member_of([:user, :agent]),
          roles <- subset([:staff]),
          t1 <- member_of([nil, :owner, :admin, :member, :guest]),
          t2 <- member_of([nil, :owner, :member, :guest]),
          credential <- v2_credential()
        ) do
      memberships =
        for {tenant, role} <- [{"t1", t1}, {"t2", t2}],
            role != nil,
            into: %{},
            do: {tenant, [role]}

      %{
        type: :user,
        id: id,
        kind: kind,
        roles: roles,
        memberships: memberships,
        credential: credential
      }
    end
  end

  defp v2_credential do
    one_of([
      constant(nil),
      gen all(
            method <- member_of([:session, :api_key, :oauth]),
            scopes <- one_of([constant(:all), subset(["docs:read", "docs:write"])]),
            tenant <- member_of([nil | @v2_tenants])
          ) do
        %Warden.Credential{method: method, scopes: scopes, tenant: tenant}
      end
    ])
  end

  defp v2_actor_spec do
    one_of([
      constant(%{type: :anonymous}),
      v2_user_spec(),
      gen all(kind <- member_of([:webhook, :system]), tenant <- member_of([nil | @v2_tenants])) do
        %{type: :system, kind: kind, tenant: tenant}
      end,
      gen all(agent <- v2_user_spec(), user <- v2_user_spec()) do
        %{type: :delegated, actor: agent, delegator: user}
      end
    ])
  end

  defp v2_rule_gen do
    leaf =
      one_of([
        constant(:public),
        constant(:authenticated),
        constant({:role, :staff}),
        constant(:session),
        map(member_of(["docs:read", "docs:write"]), &{:credential_scope, &1}),
        map(non_empty_subset([:user, :agent, :webhook, :anonymous]), &{:kind, &1}),
        map(member_of([:owner, :admin, :member, :guest]), &{:tenant_role, &1, []}),
        map(member_of([:admin, :guest]), &{:tenant_role, &1, [tenant: {:arg, [:workspace]}]}),
        constant({:check, :mine, []}),
        constant({:check, :visible, []}),
        constant({:check, :hooked, []}),
        map(member_of([:read, :write]), &{:can, Warden.Test.V2.Docs, &1, []})
      ])

    tree(leaf, fn child ->
      one_of([
        map(list_of(child, min_length: 1, max_length: 3), &{:all, &1}),
        map(list_of(child, min_length: 1, max_length: 3), &{:any, &1})
      ])
    end)
  end

  defp v2_doc do
    gen all(
          id <- integer(1..1000),
          workspace <- member_of(@v2_tenants),
          owner <- member_of(["abby", "sam", "olivia"]),
          public <- boolean(),
          visible <- boolean()
        ) do
      %Warden.Test.V2.Doc{
        id: id,
        workspace_id: workspace,
        owner_id: owner,
        public: public,
        visible: visible
      }
    end
  end

  defp v2_build(%{type: :anonymous}), do: Warden.actor(%{}, authorizer: Warden.Test.V2.Authz)

  defp v2_build(%{type: :user} = spec) do
    user = Map.take(spec, [:id, :kind, :roles, :memberships])

    Warden.actor(%{current_user: user, credential: spec.credential},
      authorizer: Warden.Test.V2.Authz
    )
  end

  defp v2_build(%{type: :system} = spec),
    do: Warden.system_actor(Warden.Test.V2.Authz, kind: spec.kind, tenant: spec.tenant)

  defp v2_build(%{type: :delegated} = spec),
    do: Warden.on_behalf_of(v2_build(spec.actor), v2_build(spec.delegator))

  defp v2_kind(%{type: :anonymous}), do: :anonymous
  defp v2_kind(%{type: :system, kind: kind}), do: kind
  defp v2_kind(%{type: :user, kind: kind}), do: kind

  defp v2_bound(%{type: :user, credential: %Warden.Credential{tenant: tenant}}), do: tenant
  defp v2_bound(%{type: :system, tenant: tenant}), do: tenant
  defp v2_bound(_spec), do: nil

  defp v2_user?(spec), do: spec.type == :user

  defp v2_has_tenant_role?(spec, tenant, role) do
    held =
      spec
      |> Map.get(:memberships, %{})
      |> Map.get(tenant, [])
      |> Enum.map(&Map.fetch!(@v2_tenant_ranks, &1))

    bound = v2_bound(spec)

    v2_user?(spec) and tenant != nil and (bound == nil or bound == tenant) and
      Enum.any?(held, &(&1 >= Map.fetch!(@v2_tenant_ranks, role)))
  end

  defp v2_session?(%{type: :user, credential: nil}), do: true
  defp v2_session?(%{type: :user, credential: %{method: :session}}), do: true
  defp v2_session?(_spec), do: false

  defp v2_scope?(%{type: :user, credential: %{scopes: :all}}, _scope), do: true

  defp v2_scope?(%{type: :user, credential: %{scopes: scopes}} = spec, scope),
    do: v2_session?(spec) or scope in scopes

  defp v2_scope?(spec, _scope), do: v2_session?(spec)

  defp v2_policy?(spec, action, doc) do
    bound = v2_bound(spec)
    in_tenant? = bound == nil or bound == doc.workspace_id
    in_tenant? and v2_policy_decides?(spec, action, doc)
  end

  defp v2_policy_decides?(%{type: :system, kind: :webhook}, action, doc),
    do: action == :read and doc.public

  defp v2_policy_decides?(%{type: :system}, _action, _doc), do: false
  defp v2_policy_decides?(spec, :read, doc), do: doc.public or Map.get(spec, :id) == doc.owner_id
  defp v2_policy_decides?(spec, :write, doc), do: spec.type == :user and spec.id == doc.owner_id

  defp v2_oracle(rule, %{type: :delegated} = spec, doc, args),
    do: v2_oracle(rule, spec.actor, doc, args) and v2_oracle(rule, spec.delegator, doc, args)

  # A bound actor denies every leaf but public() for a doc of another tenant.
  defp v2_oracle(rule, spec, doc, args)
       when not is_tuple(rule) or elem(rule, 0) not in [:all, :any] do
    bound = v2_bound(spec)

    cond do
      rule == :public -> true
      bound != nil and doc.workspace_id != bound -> false
      true -> v2_leaf(rule, spec, doc, args)
    end
  end

  defp v2_oracle({:all, rules}, spec, doc, args),
    do: Enum.all?(rules, &v2_oracle(&1, spec, doc, args))

  defp v2_oracle({:any, rules}, spec, doc, args),
    do: Enum.any?(rules, &v2_oracle(&1, spec, doc, args))

  defp v2_leaf(:public, _spec, _doc, _args), do: true
  defp v2_leaf(:authenticated, spec, _doc, _args), do: v2_user?(spec)
  defp v2_leaf({:role, role}, spec, _doc, _args), do: v2_user?(spec) and role in spec.roles
  defp v2_leaf(:session, spec, _doc, _args), do: v2_session?(spec)
  defp v2_leaf({:credential_scope, scope}, spec, _doc, _args), do: v2_scope?(spec, scope)
  defp v2_leaf({:kind, kinds}, spec, _doc, _args), do: v2_kind(spec) in kinds

  defp v2_leaf({:tenant_role, role, []}, spec, doc, _args),
    do: v2_has_tenant_role?(spec, doc.workspace_id, role)

  defp v2_leaf({:tenant_role, role, [tenant: {:arg, [:workspace]}]}, spec, _doc, args),
    do: v2_has_tenant_role?(spec, args[:workspace], role)

  defp v2_leaf({:check, :mine, []}, spec, doc, _args),
    do: v2_user?(spec) and spec.id == doc.owner_id

  defp v2_leaf({:check, :visible, []}, spec, doc, _args),
    do: spec.type != :system and doc.visible

  defp v2_leaf({:check, :hooked, []}, spec, _doc, _args),
    do: spec.type != :system or spec.kind == :webhook

  defp v2_leaf({:can, _policy, action, []}, spec, doc, _args), do: v2_policy?(spec, action, doc)

  property "0.2 rule terms agree with an independent evaluator, one value and lists" do
    check all(
            spec <- v2_actor_spec(),
            rule <- v2_rule_gen(),
            docs <- list_of(v2_doc(), min_length: 1, max_length: 6),
            workspace <- member_of([nil | @v2_tenants]),
            max_runs: @runs
          ) do
      actor = v2_build(spec)
      args = %{workspace: workspace}
      expected = Enum.filter(docs, &v2_oracle(rule, spec, &1, args))
      label = "rule: #{inspect(rule)}, actor: #{inspect(spec)}"

      for doc <- docs do
        decision = Warden.authorize(actor, rule, value: doc, args: args) == :ok
        assert decision == v2_oracle(rule, spec, doc, args), label

        assert Warden.explain(actor, rule, value: doc, args: args).result ==
                 if(decision, do: :ok, else: :deny),
               label
      end

      assert Warden.filter(actor, rule, docs, args: args) == expected, label
    end
  end

  property "delegation is never wider than either actor" do
    check all(
            agent <- v2_user_spec(),
            user <- v2_user_spec(),
            rule <- v2_rule_gen(),
            docs <- list_of(v2_doc(), min_length: 1, max_length: 4),
            max_runs: @runs
          ) do
      agent_actor = v2_build(agent)
      user_actor = v2_build(user)
      delegated = Warden.on_behalf_of(agent_actor, user_actor)
      args = %{workspace: "t1"}

      for doc <- docs do
        both? =
          Warden.allowed?(agent_actor, rule, value: doc, args: args) and
            Warden.allowed?(user_actor, rule, value: doc, args: args)

        assert Warden.allowed?(delegated, rule, value: doc, args: args) == both?, inspect(rule)
      end

      for kept <- Warden.filter(delegated, rule, docs, args: args) do
        assert Warden.allowed?(agent_actor, rule, value: kept, args: args)
        assert Warden.allowed?(user_actor, rule, value: kept, args: args)
      end
    end
  end
end
