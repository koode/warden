defmodule Warden.RedteamFuzz.FuzzTest do
  @moduledoc """
  Red-team fuzzing of `Warden.Test.FZ.Schema`.

  Random actors, random denial-handler modes (default, `:null`, `{:replace, v}`, and an
  always-error handler) and random documents: queries, mutations with a side-effect
  probe, and subscriptions with several subscribers sharing a `context_id`. Documents
  use aliases, inline and named fragments on interfaces, unions and objects, nested
  lists of abstract types, every list policy, arguments as literals, variables (with and
  without defaults, provided or not, explicit nulls), and nested input objects.

  The oracle is written without Warden: it hard-codes what the schema's rules mean as
  plain boolean functions and renders the expected response by walking the document
  over the data graph, including GraphQL null propagation.

  Each property first asserts SAFETY (every non-null value in the response is one the
  oracle allows at that position), then EXACTNESS (the response equals the oracle).
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Warden.Test.FZ.Data
  alias Warden.Test.Pubsub

  @schema Warden.Test.FZ.Schema
  @runs String.to_integer(System.get_env("WARDEN_REDTEAM_RUNS", "3000"))
  @modes [:error, :null, :replace, :strict_error]

  ## ------------------------------------------------------------------
  ## Oracle: the policy, hand-coded
  ## ------------------------------------------------------------------

  defp roles(nil), do: []
  defp roles(a), do: if(:a in a.roles, do: Enum.uniq([:b | a.roles]), else: a.roles)

  defp role?(a, r), do: r in roles(a)
  defp any_role?(a), do: Enum.any?([:a, :b, :c], &role?(a, &1))

  defp perm?(nil, _), do: false
  defp perm?(a, p), do: role?(a, :a) or p in a.perms or (p == "p1" and role?(a, :b))

  defp owns?(nil, _), do: false
  defp owns?(a, e), do: e.owner == a.id

  # Rules on the abstract type a value is reached through.
  defp abstract_ok?(:hit, a), do: a != nil
  defp abstract_ok?(:owned, a), do: any_role?(a)
  defp abstract_ok?(_, _a), do: true

  # Rules of the concrete type (own rule AND rules of interfaces it implements).
  defp concrete_ok?(%{kind: :doc} = e, a), do: (role?(a, :b) or owns?(a, e)) and any_role?(a)
  defp concrete_ok?(%{kind: :file}, a), do: perm?(a, "p1") and any_role?(a)
  defp concrete_ok?(%{kind: :note}, _a), do: true

  # Field rules (the object's own field rule AND the interface field rules).
  defp field_ok?(:label, %{kind: :doc}, a), do: a != nil and role?(a, :c)
  defp field_ok?(:label, %{kind: :file}, a), do: role?(a, :c)
  defp field_ok?(:label, %{kind: :note}, a), do: role?(a, :c) and perm?(a, "p3")
  defp field_ok?(:owner_name, _e, a), do: a != nil
  defp field_ok?(:secret_doc, _e, a), do: perm?(a, "p2")
  defp field_ok?(:blob, _e, a), do: role?(a, :a)
  defp field_ok?(:text, e, a), do: owns?(a, e)
  defp field_ok?(_, _e, _a), do: true

  ## Shapes: {type shape, list policy}

  @object_fields %{
    doc: %{
      files: {{:list, {:nn, {:named, :file}}}, :filter},
      related: {{:list, {:named, :item}}, :null_item},
      hits: {{:list, {:list, {:named, :hit}}}, :fail_list}
    },
    file: %{
      parent: {{:named, :doc}, :null_item},
      siblings: {{:nn, {:list, {:named, :file}}}, :fail_list}
    },
    note: %{
      docs: {{:list, {:nn, {:named, :doc}}}, :null_item},
      text: {{:nn, :scalar}, :null_item}
    }
  }

  @roots %{
    items: {{:list, {:named, :item}}, :null_item},
    items_filtered: {{:list, {:nn, {:named, :item}}}, :filter},
    items_strict: {{:list, {:named, :item}}, :fail_list},
    owned: {{:list, {:named, :owned}}, :null_item},
    hits: {{:list, {:named, :hit}}, :filter},
    hits_nn: {{:list, {:nn, {:named, :hit}}}, :null_item},
    node: {{:named, :item}, :null_item},
    doc: {{:named, :doc}, :null_item},
    vault: {{:named, :doc}, :null_item},
    status_items: {{:list, {:named, :note}}, :null_item},
    matrix: {{:list, {:list, {:nn, {:named, :hit}}}}, :null_item},
    touch: {{:named, :item}, :null_item},
    purge: {{:named, :doc}, :null_item},
    annotate: {{:named, :note}, :null_item},
    rotate: {{:named, :file}, :null_item},
    item_updated: {{:named, :item}, :null_item},
    doc_updated: {{:named, :doc}, :null_item},
    hit_updated: {{:named, :hit}, :null_item}
  }

  @possible %{
    item: [:doc, :file, :note],
    owned: [:doc, :file],
    hit: [:doc, :file, :note],
    doc: [:doc],
    file: [:file],
    note: [:note]
  }

  @mutations [:touch, :purge, :annotate, :rotate]

  ## Effective argument values (variables, defaults, explicit nulls)

  @arg_defaults %{limit: 10, reveal: false, status: {:enum, :published}, force: false}
  @input_defaults %{
    item_filter: %{include_hidden: false},
    annotate_input: %{pin: false},
    tag_input: %{secret: false}
  }

  # Returns {:present, value} or :absent.
  defp eff_raw(:omit), do: :absent
  defp eff_raw({:lit, v}), do: {:present, v}
  defp eff_raw({:var, _t, _d, {:provided, v}}), do: {:present, v}
  defp eff_raw({:var, _t, {:default, v}, :not_provided}), do: {:present, v}
  defp eff_raw({:var, _t, :none, :not_provided}), do: :absent

  defp eff_arg(args, name) do
    case eff_raw(Map.get(args, name, :omit)) do
      {:present, v} -> v
      :absent -> Map.get(@arg_defaults, name)
    end
  end

  defp fill_input(nil, _type), do: nil

  defp fill_input(map, type) when is_map(map) do
    Map.merge(Map.get(@input_defaults, type, %{}), map)
  end

  defp filter_ok?(nil, _a), do: true

  defp filter_ok?(f, a) do
    f = fill_input(f, :item_filter)

    (f.include_hidden == false or role?(a, :a)) and
      (not Map.has_key?(f, :owner) or a != nil) and
      Enum.all?(Map.get(f, :and) || [], &filter_ok?(&1, a))
  end

  defp annotate_ok?(input, a) do
    input = fill_input(input, :annotate_input)

    (input.pin == false or role?(a, :c)) and
      Enum.all?(Map.get(input, :tags) || [], fn tag ->
        fill_input(tag, :tag_input).secret == false or perm?(a, "p2")
      end)
  end

  # Pre checks of a root field, in Warden's order: root type rule, field rule, args.
  defp root_pre(name, args, a) do
    cond do
      not root_type_ok?(name, a) -> {:deny, :object}
      not root_field_ok?(name, a) -> {:deny, :field}
      not root_args_ok?(name, args, a) -> {:deny, :argument}
      true -> :ok
    end
  end

  defp root_type_ok?(name, a), do: name not in @mutations or any_role?(a)

  defp root_field_ok?(:vault, a), do: role?(a, :a)
  defp root_field_ok?(:touch, a), do: a != nil
  defp root_field_ok?(:purge, a), do: role?(a, :b)
  defp root_field_ok?(:doc_updated, a), do: a != nil
  # Decision 9: the :hit union's value-independent rule (authenticated) refuses the
  # subscription up front.
  defp root_field_ok?(:hit_updated, a), do: a != nil
  defp root_field_ok?(_name, _a), do: true

  defp root_args_ok?(:items, args, a) do
    (eff_arg(args, :limit) == 10 or role?(a, :b)) and filter_ok?(eff_arg(args, :filter), a)
  end

  defp root_args_ok?(name, args, a) when name in [:doc, :doc_updated],
    do: eff_arg(args, :reveal) == false or role?(a, :c)

  defp root_args_ok?(:status_items, args, a),
    do: eff_arg(args, :status) == {:enum, :published} or role?(a, :a)

  defp root_args_ok?(:purge, args, a), do: eff_arg(args, :force) == false or role?(a, :a)
  defp root_args_ok?(:annotate, args, a), do: annotate_ok?(eff_arg(args, :input), a)
  defp root_args_ok?(_name, _args, _a), do: true

  defp root_value(name, _args, _published)
       when name in [:items, :items_filtered, :items_strict, :hits, :hits_nn],
       do: Data.all()

  defp root_value(:owned, _args, _published),
    do: Enum.filter(Data.all(), &(&1.kind in [:doc, :file]))

  defp root_value(:node, args, _published), do: entity_in(eff_arg(args, :id), Data.ids())

  defp root_value(name, args, _published) when name in [:doc, :purge],
    do: entity_in(eff_arg(args, :id), Data.ids_of(:doc))

  defp root_value(:annotate, args, _published),
    do: entity_in(eff_arg(args, :input).id, Data.ids_of(:note))

  defp root_value(:rotate, args, _published),
    do: entity_in(eff_arg(args, :id), Data.ids_of(:file))

  defp root_value(:touch, args, _published), do: Data.lookup(eff_arg(args, :id))
  defp root_value(:vault, _args, _published), do: Data.entity("d2")

  defp root_value(:status_items, _args, _published),
    do: Enum.filter(Data.all(), &(&1.kind == :note))

  defp root_value(:matrix, _args, _published), do: Data.matrix()

  defp root_value(name, _args, published)
       when name in [:item_updated, :doc_updated, :hit_updated],
       do: published

  defp entity_in(id, ids), do: if(id in ids, do: Data.entity(id))

  ## Oracle: expected data

  defp expect_root(name, args, sel, o, published) do
    {shape, policy} = Map.fetch!(@roots, name)

    value =
      case root_pre(name, args, o.actor) do
        :ok ->
          if name in @mutations, do: Process.put(:fz_expected_effects, [name | effects()])
          {:value, root_value(name, args, published)}

        {:deny, :field} ->
          stat(:denial)

          if o.mode == :replace do
            stat(:replace)
            {:value, Data.replacement(name)}
          else
            :denied
          end

        {:deny, _} ->
          stat(:denial)
          :denied
      end

    case value do
      :denied -> nil
      {:value, v} -> v |> complete(shape, policy, sel, o, 0) |> finish(shape) |> unwrap_root()
    end
  end

  defp effects, do: Process.get(:fz_expected_effects, [])

  # Root fields are nullable, so a bubble stops at the root field.
  defp unwrap_root({:ok, v}), do: v
  defp unwrap_root(:bubble), do: nil

  defp finish({:ok, v}, _shape), do: {:ok, v}
  defp finish(:bubble, _shape), do: :bubble

  defp finish(r, shape) when r in [:fail_list, :list_null] do
    if match?({:nn, _}, shape), do: :bubble, else: {:ok, nil}
  end

  # complete/6 returns {:ok, value} | :bubble | :filter | :fail_list | :list_null.
  # `depth` is the list nesting depth of this position inside its field (0 = not in a
  # list).
  defp complete(v, {:nn, inner}, p, sel, o, depth) do
    case complete(v, inner, p, sel, o, depth) do
      {:ok, nil} ->
        stat(:bubble)
        :bubble

      other ->
        other
    end
  end

  defp complete(nil, _shape, _p, _sel, _o, _depth), do: {:ok, nil}
  defp complete(v, :scalar, _p, _sel, _o, _depth), do: {:ok, v}

  defp complete(vs, {:list, inner}, p, sel, o, depth) when is_list(vs) do
    results = Enum.map(vs, &complete(&1, inner, p, sel, o, depth + 1))

    cond do
      :fail_list in results ->
        stat(:fail_list)
        :fail_list

      Enum.any?(results, &(&1 in [:bubble, :list_null])) ->
        # Absinthe nulls the whole list field when a non-null item at any depth is
        # null (`null_allowed_in_list?/1` only looks at the innermost item type).
        :list_null

      true ->
        if :filter in results, do: stat(:filtered)
        {:ok, for({:ok, v} <- results, do: v)}
    end
  end

  defp complete(e, {:named, t}, p, sel, o, depth) do
    if t in [:item, :owned, :hit], do: stat(:abstract)

    if abstract_ok?(t, o.actor) and concrete_ok?(e, o.actor) do
      complete_visible(e, sel, o, depth)
    else
      stat(:denial)
      complete_denied(p, o, depth)
    end
  end

  defp complete_visible(e, sel, o, depth) do
    case render_fields(e, sel, o) do
      {:ok, m} ->
        {:ok, m}

      {:bubble, m} when depth >= 2 ->
        # Absinthe quirk: objects two or more list levels deep are never trimmed when
        # one of their non-null fields is null (`propagate_null_trimming` only visits the
        # direct values of the field's list). Spec: the object is null.
        stat(:fold_quirk)
        {:ok, {:quirk, m}}

      {:bubble, _m} ->
        {:ok, nil}
    end
  end

  defp complete_denied(p, o, depth) do
    cond do
      depth > 0 and p == :filter and o.mode != :strict_error -> :filter
      depth > 0 and p == :fail_list -> :fail_list
      true -> {:ok, nil}
    end
  end

  defp render_fields(e, sel, o) do
    sel
    |> collect(e.kind)
    |> Enum.reduce({:ok, %{}}, fn {key, name, args, sub}, {tag, acc} ->
      case field_result(e, name, args, sub, o) do
        {:ok, v} -> {tag, Map.put(acc, key, v)}
        :bubble -> {:bubble, Map.put(acc, key, nil)}
      end
    end)
  end

  defp field_result(e, :__typename, _args, _sub, _o), do: {:ok, type_name(e.kind)}

  defp field_result(e, name, args, sub, o) do
    {shape, policy} = Map.get(Map.fetch!(@object_fields, e.kind), name, {:scalar, :null_item})

    case field_pre(e, name, args, o) |> field_pre_value(e, name, o) do
      :denied -> if match?({:nn, _}, shape), do: :bubble, else: {:ok, nil}
      {:value, v} -> v |> complete(shape, policy, sub, o, 0) |> finish(shape)
    end
  end

  defp field_pre(e, name, args, o) do
    cond do
      not field_ok?(name, e, o.actor) ->
        {:deny, :field}

      # Decision 5: an argument without a default is restricted whenever it is present,
      # explicit null included.
      name == :related and match?({:present, _}, eff_raw(Map.get(args, :kind, :omit))) and
          not perm?(o.actor, "p3") ->
        {:deny, :argument}

      true ->
        :ok
    end
  end

  defp field_pre_value(:ok, e, name, _o), do: {:value, field_value(e, name)}

  defp field_pre_value({:deny, :field}, _e, name, o) do
    stat(:denial)

    if o.mode == :replace do
      stat(:replace)
      {:value, Data.replacement(name)}
    else
      :denied
    end
  end

  defp field_pre_value({:deny, :argument}, _e, _name, _o) do
    stat(:denial)
    :denied
  end

  defp field_value(e, :id), do: e.id

  defp field_value(e, name) when name in [:files, :related, :siblings, :docs],
    do: e |> Map.fetch!(name) |> Enum.map(&Data.entity/1)

  defp field_value(e, :hits), do: Enum.map(e.hits, fn row -> Enum.map(row, &Data.entity/1) end)
  defp field_value(e, :parent), do: Data.entity(e.parent)
  defp field_value(e, name), do: Map.fetch!(e, name)

  # Field collection: a fragment applies when the concrete type is a possible type of
  # its condition. Fields with the same response key merge their sub-selections.
  defp collect(sel, kind) do
    sel
    |> do_collect(kind)
    |> Enum.reduce({[], %{}}, fn {key, name, args, sub}, {order, acc} ->
      case acc do
        %{^key => {^name, a, subs}} -> {order, Map.put(acc, key, {name, a, subs ++ (sub || [])})}
        _ -> {order ++ [key], Map.put(acc, key, {name, args, sub || []})}
      end
    end)
    |> then(fn {order, acc} ->
      Enum.map(order, fn key ->
        {name, args, subs} = acc[key]
        {key, name, args, subs}
      end)
    end)
  end

  defp do_collect(sel, kind) do
    Enum.flat_map(sel, fn
      {:field, {key, _}, name, args, sub} ->
        [{key, name, args, sub}]

      {frag, cond, sub} when frag in [:inline, :spread] ->
        if kind in @possible[frag_cond(cond)], do: do_collect(sub, kind), else: []
    end)
  end

  defp frag_cond({cond, _name}), do: cond
  defp frag_cond(cond), do: cond

  defp type_name(:doc), do: "Doc"
  defp type_name(:file), do: "File"
  defp type_name(:note), do: "Note"
  defp type_name(:item), do: "Item"
  defp type_name(:owned), do: "Owned"
  defp type_name(:hit), do: "Hit"

  ## ------------------------------------------------------------------
  ## Generators
  ## ------------------------------------------------------------------

  @scalars %{
    item: [:id, :title, :label, :__typename],
    owned: [:id, :owner_name, :__typename],
    hit: [:__typename],
    doc: [:id, :title, :label, :owner_name, :secret_doc, :__typename],
    file: [:id, :title, :label, :owner_name, :blob, :__typename],
    note: [:id, :title, :label, :text, :__typename]
  }

  @objects %{
    item: [],
    owned: [],
    hit: [],
    doc: [files: :file, related: :item, hits: :hit],
    file: [parent: :doc, siblings: :file],
    note: [docs: :doc]
  }

  defp conditions(ctx) do
    for {cond, possible} <- @possible,
        possible -- (possible -- @possible[ctx]) != [],
        do: cond
  end

  defp bool_lit, do: one_of([constant(nil), boolean()])

  # :omit | {:lit, v} | {:var, gql_type, :none | {:default, v}, :not_provided | {:provided, v}}
  defp arg_value(gql_type, lit_gen) do
    frequency([
      {2, constant(:omit)},
      {3, map(lit_gen, &{:lit, &1})},
      {3,
       gen all(
             d <- one_of([constant(:none), map(lit_gen, &{:default, &1})]),
             p <- one_of([constant(:not_provided), map(lit_gen, &{:provided, &1})])
           ) do
         {:var, gql_type, d, p}
       end}
    ])
  end

  defp optional_fields(fields) do
    fields
    |> Enum.map(fn {k, g} -> map(one_of([constant(:omit), g]), &{k, &1}) end)
    |> fixed_list()
    |> map(fn kvs -> for {k, v} <- kvs, v != :omit, into: %{}, do: {k, v} end)
  end

  defp item_filter(depth) do
    base = [
      kind: one_of([constant("x"), constant(nil)]),
      include_hidden: bool_lit(),
      owner: one_of([constant("u1"), constant(nil)])
    ]

    nested =
      if depth > 0,
        do: [and: one_of([constant(nil), list_of(item_filter(depth - 1), max_length: 2)])],
        else: []

    optional_fields(base ++ nested)
  end

  defp annotate_input do
    gen all(
          id <- member_of(["n1", "n2", "n9"]),
          rest <-
            optional_fields(
              text: one_of([constant("hi"), constant(nil)]),
              pin: bool_lit(),
              tags:
                one_of([
                  constant(nil),
                  list_of(
                    map(optional_fields(secret: bool_lit()), &Map.put(&1, :name, "t")),
                    max_length: 2
                  )
                ])
            )
        ) do
      Map.put(rest, :id, id)
    end
  end

  defp selection_set(ctx, depth) do
    scalar =
      gen all(name <- member_of(@scalars[ctx]), alias? <- boolean()) do
        {:field, alias?, name, %{}, nil}
      end

    object =
      if depth > 0 and @objects[ctx] != [] do
        [
          gen all(
                {name, type} <- member_of(@objects[ctx]),
                alias? <- boolean(),
                args <-
                  if(name == :related,
                    do:
                      map(
                        arg_value("String", one_of([constant("x"), constant(nil)])),
                        &%{kind: &1}
                      ),
                    else: constant(%{})
                  ),
                sub <- selection_set(type, depth - 1)
              ) do
            # Fields with arguments always get a unique alias so they never merge.
            {:field, alias? or args != %{}, name, args, sub}
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
                cond <- member_of(conditions(ctx)),
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

  defp query_root do
    one_of([
      gen all(
            filter <- arg_value("ItemFilter", one_of([constant(nil), item_filter(2)])),
            limit <- arg_value("Int", member_of([10, 5, nil])),
            sel <- selection_set(:item, 3)
          ) do
        {:items, %{filter: filter, limit: limit}, sel}
      end,
      map(selection_set(:item, 3), &{:items_filtered, %{}, &1}),
      map(selection_set(:item, 3), &{:items_strict, %{}, &1}),
      map(selection_set(:owned, 3), &{:owned, %{}, &1}),
      map(selection_set(:hit, 3), &{:hits, %{}, &1}),
      map(selection_set(:hit, 3), &{:hits_nn, %{}, &1}),
      gen all(id <- member_of(Data.ids() ++ ["zz"]), sel <- selection_set(:item, 3)) do
        {:node, %{id: {:lit, id}}, sel}
      end,
      gen all(
            id <- member_of(["d1", "d2", "zz"]),
            reveal <- arg_value("Boolean", bool_lit()),
            sel <- selection_set(:doc, 3)
          ) do
        {:doc, %{id: {:lit, id}, reveal: reveal}, sel}
      end,
      map(selection_set(:doc, 3), &{:vault, %{}, &1}),
      gen all(
            status <-
              arg_value(
                "Status",
                member_of([{:enum, :published}, {:enum, :draft}, nil])
              ),
            sel <- selection_set(:note, 3)
          ) do
        {:status_items, %{status: status}, sel}
      end,
      map(selection_set(:hit, 3), &{:matrix, %{}, &1})
    ])
  end

  defp mutation_root do
    one_of([
      gen all(id <- member_of(Data.ids() ++ ["zz"]), sel <- selection_set(:item, 2)) do
        {:touch, %{id: {:lit, id}}, sel}
      end,
      gen all(
            id <- member_of(["d1", "d2", "zz"]),
            force <- arg_value("Boolean", bool_lit()),
            sel <- selection_set(:doc, 2)
          ) do
        {:purge, %{id: {:lit, id}, force: force}, sel}
      end,
      gen all(
            input <-
              one_of([
                map(annotate_input(), &{:lit, &1}),
                map(annotate_input(), &{:var, "AnnotateInput!", :none, {:provided, &1}})
              ]),
            sel <- selection_set(:note, 2)
          ) do
        {:annotate, %{input: input}, sel}
      end,
      gen all(id <- member_of(["f1", "f2"]), sel <- selection_set(:file, 2)) do
        {:rotate, %{id: {:lit, id}}, sel}
      end
    ])
  end

  defp subscription_root do
    one_of([
      map(selection_set(:item, 3), &{:item_updated, %{}, &1}),
      gen all(reveal <- arg_value("Boolean", bool_lit()), sel <- selection_set(:doc, 3)) do
        {:doc_updated, %{reveal: reveal}, sel}
      end,
      map(selection_set(:hit, 3), &{:hit_updated, %{}, &1})
    ])
  end

  defp subset(items) do
    map(list_of(boolean(), length: length(items)), fn bits ->
      for {item, true} <- Enum.zip(items, bits), do: item
    end)
  end

  defp actor do
    frequency([
      {1, constant(nil)},
      {4,
       gen all(
             id <- member_of(["u1", "u2", "u3"]),
             roles <- subset([:a, :b, :c]),
             perms <- subset(["p1", "p2", "p3"])
           ) do
         %{id: id, roles: roles, perms: perms}
       end}
    ])
  end

  # Several subscribers to one document. Half of them reuse one base actor (or the
  # base actor with different roles or permissions), so subscriptions that share a
  # `context_id` are common.
  defp subscribers do
    gen all(
          base <- actor(),
          variants <-
            list_of(
              one_of([
                constant(base),
                actor(),
                map(subset([:a, :b, :c]), fn roles -> base && %{base | roles: roles} end),
                map(subset(["p1", "p2", "p3"]), fn perms -> base && %{base | perms: perms} end)
              ]),
              min_length: 2,
              max_length: 4
            )
        ) do
      variants
    end
  end

  ## ------------------------------------------------------------------
  ## Rendering the document
  ## ------------------------------------------------------------------

  defp new_state, do: %{n: 0, frags: [], vars: %{}, decls: []}

  defp render_op(op, raw_roots, extra_args \\ %{}) do
    {roots, st} =
      Enum.map_reduce(raw_roots, new_state(), fn {name, args, sel}, st ->
        st = %{st | n: st.n + 1}
        key = "r#{st.n}"
        {args_src, st} = render_args(Map.merge(args, extra_args), st)
        {sel, st} = keyed(sel, st)
        {{:root, key, name, args, args_src, sel}, st}
      end)

    body =
      Enum.map_join(roots, " ", fn {:root, key, name, _args, args_src, sel} ->
        "#{key}: #{camel(name)}#{args_src} #{render_sel(sel)}"
      end)

    header =
      case st.decls do
        [] -> op
        decls -> "#{op}(#{Enum.join(Enum.reverse(decls), ", ")})"
      end

    frags =
      Enum.map_join(Enum.reverse(st.frags), "\n", fn {name, cond, sel} ->
        "fragment #{name} on #{type_name(cond)} #{render_sel(sel)}"
      end)

    {"#{header} { #{body} }\n#{frags}", roots, st.vars}
  end

  defp keyed(sel, st) do
    Enum.map_reduce(sel, st, fn
      {:field, alias?, name, args, sub}, st ->
        st = %{st | n: st.n + 1}
        key = if alias?, do: "k#{st.n}", else: camel(name)
        {args_src, st} = render_args(args, st)
        {sub, st} = if sub, do: keyed(sub, st), else: {nil, st}
        {{:field, {key, alias?}, name, {args, args_src}, sub}, st}

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

  defp render_args(args, st) do
    {parts, st} =
      args
      |> Enum.sort()
      |> Enum.flat_map_reduce(st, fn
        {_k, :omit}, st ->
          {[], st}

        {k, {:lit, v}}, st ->
          {["#{camel(k)}: #{literal(v)}"], st}

        {k, {:var, type, default, provided}}, st ->
          st = %{st | n: st.n + 1}
          name = "v#{st.n}"

          decl =
            case default do
              :none -> "$#{name}: #{type}"
              {:default, v} -> "$#{name}: #{type} = #{literal(v)}"
            end

          vars =
            case provided do
              {:provided, v} -> Map.put(st.vars, name, json(v))
              :not_provided -> st.vars
            end

          {["#{camel(k)}: $#{name}"], %{st | vars: vars, decls: [decl | st.decls]}}
      end)

    src = if parts == [], do: "", else: "(#{Enum.join(parts, ", ")})"
    {src, st}
  end

  defp literal(nil), do: "null"
  defp literal(v) when is_boolean(v) or is_integer(v), do: to_string(v)
  defp literal(v) when is_binary(v), do: inspect(v)
  defp literal({:enum, v}), do: v |> Atom.to_string() |> String.upcase()
  defp literal(l) when is_list(l), do: "[" <> Enum.map_join(l, ", ", &literal/1) <> "]"

  defp literal(%{} = m),
    do:
      "{" <>
        Enum.map_join(Enum.sort(m), ", ", fn {k, v} -> "#{camel(k)}: #{literal(v)}" end) <> "}"

  defp json({:enum, v}), do: v |> Atom.to_string() |> String.upcase()
  defp json(l) when is_list(l), do: Enum.map(l, &json/1)
  defp json(%{} = m), do: Map.new(m, fn {k, v} -> {camel(k), json(v)} end)
  defp json(v), do: v

  defp render_sel(sel) do
    inner =
      Enum.map_join(sel, " ", fn
        {:field, {key, true}, name, {_, args_src}, sub} ->
          "#{key}: #{camel(name)}#{args_src}#{render_sub(sub)}"

        {:field, {_key, false}, name, {_, args_src}, sub} ->
          "#{camel(name)}#{args_src}#{render_sub(sub)}"

        {:inline, cond, sub} ->
          "... on #{type_name(cond)} #{render_sel(sub)}"

        {:spread, {_cond, name}, _sub} ->
          "...#{name}"
      end)

    "{ #{inner} }"
  end

  defp render_sub(nil), do: ""
  defp render_sub(sub), do: " " <> render_sel(sub)

  defp camel(:__typename), do: "__typename"
  defp camel(atom), do: atom |> Atom.to_string() |> Absinthe.Utils.camelize(lower: true)

  # Normalise keyed selections to the oracle's shape.
  defp oracle_sel(nil), do: nil

  defp oracle_sel(sel) do
    Enum.map(sel, fn
      {:field, kinfo, name, {args, _src}, sub} -> {:field, kinfo, name, args, oracle_sel(sub)}
      {:inline, cond, sub} -> {:inline, cond, oracle_sel(sub)}
      {:spread, cond, sub} -> {:spread, cond, oracle_sel(sub)}
    end)
  end

  defp expected_data(roots, o, published \\ nil) do
    Map.new(roots, fn {:root, key, name, args, _src, sel} ->
      {key, expect_root(name, args, oracle_sel(sel), o, published)}
    end)
  end

  ## ------------------------------------------------------------------
  ## Comparison helpers
  ## ------------------------------------------------------------------

  # Safety: every non-null value in `resp` is allowed by `exp` at the same position.
  defp safe?(nil, _exp), do: true
  defp safe?(resp, {:quirk, m}), do: safe?(resp, m)

  defp safe?(resp, exp) when is_map(resp),
    do:
      is_map(exp) and Enum.all?(resp, fn {k, v} -> Map.has_key?(exp, k) and safe?(v, exp[k]) end)

  defp safe?(resp, exp) when is_list(resp),
    do:
      is_list(exp) and length(resp) == length(exp) and
        Enum.all?(Enum.zip(resp, exp), fn {r, e} -> safe?(r, e) end)

  defp safe?(resp, exp), do: resp == exp

  # The oracle marks positions where Absinthe does not fold a null non-null field into
  # its parent object (nested lists). Exactness compares against Absinthe's rendering;
  # the spec deviation itself is asserted in rajska_regressions_test.exs.
  defp normalize({:quirk, m}), do: normalize(m)
  defp normalize(m) when is_map(m), do: Map.new(m, fn {k, v} -> {k, normalize(v)} end)
  defp normalize(l) when is_list(l), do: Enum.map(l, &normalize/1)
  defp normalize(v), do: v

  defp check_errors(result, mode) do
    for error <- Map.get(result, :errors, []) do
      allowed =
        if mode == :null,
          do: ["Cannot return null for non-nullable field"],
          else: ["Forbidden", "Cannot return null for non-nullable field"]

      assert error.message in allowed, "unexpected error in mode #{mode}: #{inspect(error)}"
    end
  end

  defp stat(key), do: Process.put({:fz_stat, key}, true)

  defp take_stats do
    for key <- [:denial, :abstract, :filtered, :fail_list, :bubble, :replace, :fold_quirk],
        into: %{} do
      {key, Process.delete({:fz_stat, key}) == true}
    end
  end

  defp bump(name, flags) do
    stats = Process.get({:fz_totals, name}, %{})

    stats =
      Enum.reduce(flags, stats, fn
        {k, true}, s -> Map.update(s, k, 1, &(&1 + 1))
        _, s -> s
      end)

    Process.put({:fz_totals, name}, stats)
  end

  defp report(name) do
    stats = Process.get({:fz_totals, name}, %{})
    IO.puts("\n[redteam_fuzz] #{name}: #{inspect(stats, limit: :infinity)}")
    stats
  end

  defp describe(o, doc, vars, extra) do
    """
    actor: #{inspect(o.actor)}
    deny mode: #{inspect(o.mode)}
    document: #{doc}
    variables: #{inspect(vars)}
    #{extra}
    """
  end

  defp run_doc(doc, actor, mode, vars, extra_ctx \\ %{}) do
    Process.put(:fz_deny_mode, mode)

    context = Map.merge(%{actor: actor, test_pid: self()}, extra_ctx)
    {:ok, result} = Absinthe.run(doc, @schema, context: context, variables: vars)
    result
  end

  defp drain_effects(acc \\ []) do
    receive do
      {:fz_side_effect, tag, _args} -> drain_effects([tag | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  ## ------------------------------------------------------------------
  ## Properties
  ## ------------------------------------------------------------------

  @tag timeout: :infinity
  property "queries: no denied value appears, every allowed value does" do
    check all(
            actor <- actor(),
            mode <- member_of(@modes),
            raw_roots <- list_of(query_root(), min_length: 1, max_length: 3),
            max_runs: @runs
          ) do
      {doc, roots, vars} = render_op("query", raw_roots)
      result = run_doc(doc, actor, mode, vars)
      o = %{actor: actor, mode: mode}

      unless Map.has_key?(result, :data),
        do: flunk("document did not validate: #{inspect(result[:errors])}\n#{doc}")

      Process.delete(:fz_expected_effects)
      take_stats()
      expected = expected_data(roots, o)
      flags = take_stats()

      assert safe?(result.data, expected),
             "LEAK\n" <>
               describe(
                 o,
                 doc,
                 vars,
                 "got: #{inspect(result.data)}\nexpected: #{inspect(expected)}"
               )

      # Where Absinthe's null folding is inconsistent (see `normalize/1`), only safety
      # is asserted; the fold itself is covered by a deterministic regression test.
      unless flags.fold_quirk,
        do:
          assert(
            result.data == normalize(expected),
            "MISMATCH\n" <>
              describe(
                o,
                doc,
                vars,
                "got: #{inspect(result.data)}\nexpected: #{inspect(expected)}"
              )
          )

      check_errors(result, mode)

      bump(:queries,
        runs: true,
        fragments: String.contains?(doc, "..."),
        variables: vars != %{} or String.contains?(doc, "$"),
        null_args: String.contains?(doc, "null"),
        nested_lists: String.contains?(doc, "matrix") or String.contains?(doc, "hits"),
        errors: Map.has_key?(result, :errors)
      )

      bump(:queries, Map.to_list(flags))
    end

    stats = report(:queries)
    assert stats.runs >= @runs
    assert Map.get(stats, :denial, 0) > div(@runs, 3), inspect(stats)
    assert Map.get(stats, :fragments, 0) > div(@runs, 3), inspect(stats)
    assert Map.get(stats, :abstract, 0) > div(@runs, 3), inspect(stats)

    for key <- [:filtered, :fail_list, :bubble, :replace, :variables, :null_args] do
      assert Map.get(stats, key, 0) > div(@runs, 20), "#{key}: #{inspect(stats)}"
    end
  end

  @tag timeout: :infinity
  property "mutations: denied mutations never run their resolvers; returned data is filtered" do
    check all(
            actor <- actor(),
            mode <- member_of(@modes),
            raw_roots <- list_of(mutation_root(), min_length: 1, max_length: 3),
            max_runs: @runs
          ) do
      _ = drain_effects()
      {doc, roots, vars} = render_op("mutation", raw_roots)
      result = run_doc(doc, actor, mode, vars)
      o = %{actor: actor, mode: mode}

      unless Map.has_key?(result, :data),
        do: flunk("document did not validate: #{inspect(result[:errors])}\n#{doc}")

      ran = drain_effects()

      Process.delete(:fz_expected_effects)
      take_stats()
      expected = expected_data(roots, o)
      flags = take_stats()
      expected_effects = Enum.reverse(effects())

      assert Enum.sort(ran) -- Enum.sort(expected_effects) == [],
             "SIDE EFFECT OF A DENIED MUTATION\n" <>
               describe(
                 o,
                 doc,
                 vars,
                 "ran: #{inspect(ran)}\nallowed: #{inspect(expected_effects)}"
               )

      assert safe?(result.data, expected),
             "LEAK\n" <>
               describe(
                 o,
                 doc,
                 vars,
                 "got: #{inspect(result.data)}\nexpected: #{inspect(expected)}"
               )

      assert Enum.sort(ran) == Enum.sort(expected_effects),
             "MISSING SIDE EFFECT\n" <>
               describe(
                 o,
                 doc,
                 vars,
                 "ran: #{inspect(ran)}\nallowed: #{inspect(expected_effects)}"
               )

      # Where Absinthe's null folding is inconsistent (see `normalize/1`), only safety
      # is asserted; the fold itself is covered by a deterministic regression test.
      unless flags.fold_quirk,
        do:
          assert(
            result.data == normalize(expected),
            "MISMATCH\n" <>
              describe(
                o,
                doc,
                vars,
                "got: #{inspect(result.data)}\nexpected: #{inspect(expected)}"
              )
          )

      check_errors(result, mode)

      bump(:mutations,
        runs: true,
        blocked: length(raw_roots) > length(expected_effects),
        executed: expected_effects != [],
        fragments: String.contains?(doc, "..."),
        variables: vars != %{}
      )

      bump(:mutations, Map.to_list(flags))
    end

    stats = report(:mutations)
    assert Map.get(stats, :blocked, 0) > div(@runs, 4), inspect(stats)
    assert Map.get(stats, :executed, 0) > div(@runs, 4), inspect(stats)
  end

  @tag timeout: :infinity
  property "subscriptions: each subscriber gets its own view, even with a shared context_id" do
    check all(
            actors <- subscribers(),
            mode <- member_of(@modes),
            raw_root <- subscription_root(),
            published_id <- member_of(Data.graph_ids()),
            max_runs: @runs
          ) do
      {field, _, _} = raw_root

      published_id =
        if field == :doc_updated and Data.raw(published_id).kind != :doc,
          do: "d1",
          else: published_id

      channel = "fz#{System.unique_integer([:positive])}"
      {doc, [root], vars} = render_op("subscription", [raw_root], %{channel: {:lit, channel}})

      subs =
        Enum.map(actors, fn actor ->
          result =
            run_doc(doc, actor, mode, vars, %{pubsub: Warden.Test.Pubsub})

          {actor, result}
        end)

      topics =
        for {_actor, %{"subscribed" => topic}} <- subs, uniq: true do
          :ok = Pubsub.subscribe(topic)
          topic
        end

      Process.put(:fz_deny_mode, mode)
      published = Data.entity(published_id)
      :ok = Absinthe.Subscription.publish(Warden.Test.Pubsub, published, [{field, channel}])

      payloads =
        Map.new(topics, fn topic ->
          receive do
            {:subscription_data, ^topic, data} -> {topic, data}
          after
            1000 -> flunk("no data published to #{topic}\n#{doc}")
          end
        end)

      shared? = length(topics) < Enum.count(subs, &match?({_, %{"subscribed" => _}}, &1))

      for {actor, result} <- subs do
        o = %{actor: actor, mode: mode}
        {:root, key, name, args, _src, _sel} = root

        case root_pre(name, args, actor) do
          :ok ->
            assert %{"subscribed" => topic} = result, describe(o, doc, vars, inspect(result))
            take_stats()
            expected = %{key => expect_root(name, args, oracle_sel(elem(root, 5)), o, published)}
            flags = take_stats()
            got = payloads[topic].data

            assert safe?(got, expected),
                   "LEAK (subscription#{if shared?, do: ", shared context_id"})\n" <>
                     describe(
                       o,
                       doc,
                       vars,
                       "published: #{published_id}\ngot: #{inspect(got)}\nexpected: #{inspect(expected)}\nall actors: #{inspect(actors)}"
                     )

            unless flags.fold_quirk,
              do:
                assert(
                  got == normalize(expected),
                  "MISMATCH (subscription)\n" <>
                    describe(
                      o,
                      doc,
                      vars,
                      "published: #{published_id}\ngot: #{inspect(got)}\nexpected: #{inspect(expected)}"
                    )
                )

            bump(:subscriptions, Map.to_list(flags))

          {:deny, _} ->
            refute Map.has_key?(result, "subscribed"),
                   "SUBSCRIBED DESPITE A DENIAL\n" <> describe(o, doc, vars, inspect(result))

            assert [%{message: "Forbidden"}] = result.errors
            bump(:subscriptions, refused: true)
        end
      end

      for topic <- topics do
        Registry.unregister(Warden.Test.Pubsub.Topics, topic)
        Absinthe.Subscription.unsubscribe(Warden.Test.Pubsub, topic)
      end

      bump(:subscriptions,
        runs: true,
        shared_context_id: shared?,
        fragments: String.contains?(doc, "..."),
        variables: vars != %{}
      )
    end

    stats = report(:subscriptions)
    assert Map.get(stats, :shared_context_id, 0) > div(@runs, 10), inspect(stats)
    assert Map.get(stats, :refused, 0) > div(@runs, 10), inspect(stats)
  end
end
