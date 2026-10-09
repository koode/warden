defmodule Warden.ConfirmProbe.Authz do
  @moduledoc false
  use Warden.Authorizer,
    roles: [:admin, :viewer],
    permissions: ["p"],
    checks: [:self]

  @impl true
  def subject(ctx) do
    if Map.has_key?(ctx, :subj), do: ctx.subj, else: ctx[:current_user]
  end

  @impl true
  def roles(u, _), do: u.roles

  @impl true
  def check(:self, %Warden.Check{actor: a, value: v}),
    do: is_map(v) and Map.get(v, :id) == a.subject.id
end

defmodule Warden.ConfirmProbe.FilterAuthz do
  @moduledoc false
  use Warden.Authorizer, roles: [:admin, :viewer]

  @impl true
  def subject(ctx), do: ctx[:current_user]
  @impl true
  def roles(u, _), do: u.roles

  @impl true
  def deny(%Warden.Denial{list_policy: :filter, type: :zsecret}), do: {:error, "hidden"}
  def deny(d), do: Warden.Authorizer.default_deny(d, __warden_catalog__())
end

defmodule Warden.ConfirmProbe.NilKeyAuthz do
  @moduledoc false
  use Warden.Authorizer, roles: [:admin, :viewer]
  @impl true
  def subject(ctx), do: ctx[:current_user]
  @impl true
  def roles(u, _), do: u.roles
  @impl true
  def actor_key(_actor, _ctx), do: nil
end

defmodule Warden.Adversarial.ConfirmProbesTest do
  @moduledoc """
  Probes from the confirmer pass over the red-team fix round, kept as permanent tests.
  """
  use ExUnit.Case, async: false

  import Warden.Test.Helpers
  import Warden.Test.CompileHelpers

  alias Warden.Test.Pubsub

  @pa "authorizer: Warden.ConfirmProbe.Authz"

  defp viewer_u, do: %{id: "u2", roles: [:viewer]}
  defp admin_u, do: %{id: "u1", roles: [:admin]}

  defp go(schema, doc, user, opts \\ []) do
    ctx = Map.merge(%{current_user: user}, Keyword.get(opts, :ctx, %{}))
    vars = Keyword.get(opts, :vars, %{})
    {:ok, r} = Absinthe.run(doc, schema, context: ctx, variables: vars)
    r
  end

  # D1 -------------------------------------------------------------------------
  test "D1: a user field with an __ identifier but ordinary name is guarded" do
    s =
      compile_schema(
        """
        object :thing do
          field :__hidden, :string, name: "hiddenVal" do
            authorize role(:admin)
          end
        end

        query do
          field :__dump, :string, name: "dump" do
            authorize role(:admin)
            resolve fn _, _ -> {:ok, "DUMP"} end
          end

          field :thing, :thing, resolve: fn _, _ -> {:ok, %{__hidden: "HID"}} end
        end
        """,
        @pa
      )

    r = go(s, "{ dump }", viewer_u())
    refute contains?(r[:data], "DUMP")
  end

  # D2 -------------------------------------------------------------------------
  test "D2: custom-named root and a nested Query-named object, aliased introspection" do
    s =
      compile_schema(
        """
        object :inner, name: "Query" do
          field :x, :string
        end

        query name: "Root" do
          field :inner, :inner, resolve: fn _, _ -> {:ok, %{x: "x"}} end
        end
        """,
        @pa <> ", introspection: role(:admin)"
      )

    r =
      go(
        s,
        ~s|{ a: __type(name: "Root") { name } b: __schema { queryType { name } } }|,
        viewer_u()
      )

    refute contains?(r[:data], "Root")

    r = go(s, ~s|{ inner { t: __type(name: "Root") { name } } }|, viewer_u())
    refute contains?(r[:data], "Root")

    r = go(s, ~s|{ inner { s: __schema { queryType { name } } } }|, viewer_u())
    refute contains?(r[:data], "Root")

    r = go(s, ~s|{ inner { s: __schema { queryType { name } } } }|, admin_u())
    assert contains?(r[:data], "Root")
  end

  # D3 -------------------------------------------------------------------------
  test "D3: root rule guards __typename, __schema and __type on query and mutation roots" do
    s =
      compile_schema(
        """
        query do
          authorize role(:admin)
          field :ping, :string, resolve: fn _, _ -> {:ok, "pong"} end
        end

        mutation do
          authorize role(:admin)
          field :poke, :string, resolve: fn _, _ -> {:ok, "poked"} end
        end
        """,
        @pa
      )

    r = go(s, "{ t: __typename }", viewer_u())
    refute contains?(r[:data], "RootQueryType")

    r = go(s, "mutation { t: __typename }", viewer_u())
    refute contains?(r[:data], "RootMutationType")

    r = go(s, ~s|{ __schema { queryType { name } } }|, viewer_u())
    refute contains?(r[:data], "RootQueryType")

    r = go(s, ~s|{ __type(name: "RootQueryType") { name } }|, viewer_u())
    refute contains?(r[:data], "RootQueryType")

    assert go(s, "{ t: __typename }", admin_u()).data == %{"t" => "RootQueryType"}
  end

  # D4 / D5 ----------------------------------------------------------------------
  @iface_schema """
  interface :node do
    field :items, :string do
      arg :secret, :boolean, default_value: true
    end

    resolve_type fn _, _ -> :thing end
  end

  object :thing do
    interface :node

    field :items, :string do
      arg :secret, :boolean
      authorize_args secret: role(:admin)
      resolve fn _, args, _ -> {:ok, "ITEMS:" <> inspect(args)} end
    end
  end

  query do
    field :thing, :thing, resolve: fn _, _ -> {:ok, %{}} end
    field :node, :node, resolve: fn _, _ -> {:ok, %{}} end
  end
  """

  test "D4/D5: object arg without default, interface default true: explicit true on the concrete type" do
    s = compile_schema(@iface_schema, @pa)
    r = go(s, "{ thing { items(secret: true) } }", viewer_u())

    refute contains?(r[:data], "ITEMS:%{secret: true}"),
           "explicit secret: true bypassed: #{inspect(r)}"

    r = go(s, "{ thing { items(secret: true) } }", admin_u())
    assert r.data == %{"thing" => %{"items" => "ITEMS:%{secret: true}"}}, inspect(r)
  end

  test "D4/D5: object arg without default, interface default true: omitted through the interface" do
    s = compile_schema(@iface_schema, @pa)
    # Decided: the interface default fills secret: true and the resolver would receive
    # it, so the omitted argument is restricted too.
    r = go(s, "{ node { items } }", viewer_u())
    refute contains?(r[:data], "ITEMS:%{secret: true}"), inspect(r)
    assert r.data == %{"node" => %{"items" => nil}}, inspect(r)

    r = go(s, "{ node { items } }", admin_u())
    assert r.data == %{"node" => %{"items" => "ITEMS:%{secret: true}"}}, inspect(r)
  end

  test "D4: rule declared only on the interface arg, differing defaults, concrete selection" do
    s =
      compile_schema(
        """
        interface :node do
          field :items, :string do
            arg :secret, :boolean, default_value: true
            authorize_args secret: role(:admin)
          end

          resolve_type fn _, _ -> :thing end
        end

        object :thing do
          interface :node

          field :items, :string do
            arg :secret, :boolean, default_value: false
            resolve fn _, args, _ -> {:ok, "ITEMS:" <> inspect(args)} end
          end
        end

        query do
          field :thing, :thing, resolve: fn _, _ -> {:ok, %{}} end
          field :node, :node, resolve: fn _, _ -> {:ok, %{}} end
        end
        """,
        @pa
      )

    # Omitted through the concrete type: false fills in, differs from interface default true.
    r = go(s, "{ thing { items } }", viewer_u())
    refute contains?(r[:data], "ITEMS:%{secret: false}")
    r = go(s, "{ node { ... on Thing { items(secret: false) } } }", viewer_u())
    refute contains?(r[:data], "ITEMS:%{secret: false}")
  end

  test "D5: explicit null (literal, variable, nested input field) on args without default" do
    s =
      compile_schema(
        """
        input_object :flt do
          field :owner, :id do
            authorize role(:admin)
          end
          field :tag, :string
        end

        query do
          field :list, :string do
            arg :owner, :id
            arg :f, list_of(:flt)
            authorize_args owner: role(:admin)
            resolve fn _, args, _ -> {:ok, "LIST:" <> inspect(args)} end
          end
        end
        """,
        @pa
      )

    r = go(s, "{ list(owner: null) }", viewer_u())
    refute contains?(r[:data], "LIST:%{owner: nil}"), inspect(r)

    r = go(s, "query($o: ID) { list(owner: $o) }", viewer_u(), vars: %{"o" => nil})
    refute contains?(r[:data] || %{}, "LIST:%{owner: nil}"), inspect(r)

    # Omitted variable: the key is absent, so the rule does not apply.
    r = go(s, "query($o: ID) { list(owner: $o) }", viewer_u())
    assert r.data == %{"list" => "LIST:%{}"}, inspect(r)

    r = go(s, ~s|{ list(f: [{tag: "a"}, {owner: null}]) }|, viewer_u())
    assert r.data == %{"list" => nil}, inspect(r)

    r = go(s, ~s|{ list(f: [{tag: "a"}]) }|, viewer_u())
    assert contains?(r.data, ~s|LIST:%{f: [%{tag: "a"}]}|), inspect(r)
  end

  # D6 -------------------------------------------------------------------------
  test "D6: interface resolve_type returns a non-implementing guarded type, in a list and singly" do
    s =
      compile_schema(
        """
        interface :node do
          field :id, :id
          resolve_type fn
            %{kind: :sec}, _ -> :zsecret
            _, _ -> :pub
          end
        end

        object :pub do
          interface :node
          field :id, :id
        end

        object :zsecret do
          authorize role(:admin)
          field :id, :id
        end

        union :either do
          types [:pub]
          resolve_type fn
            %{kind: :sec}, _ -> :zsecret
            _, _ -> :pub
          end
        end

        query do
          field :node, :node, resolve: fn _, _ -> {:ok, %{kind: :sec, id: "SEC1"}} end
          field :nodes, list_of(:node), resolve: fn _, _ -> {:ok, [%{kind: :pub, id: "P1"}, %{kind: :sec, id: "SEC2"}]} end
          field :either, list_of(:either), resolve: fn _, _ -> {:ok, [%{kind: :sec, id: "SEC3"}]} end
        end
        """,
        @pa
      )

    r = go(s, "{ node { id } nodes { id __typename } either { __typename } }", viewer_u())
    refute contains?(r[:data], "SEC1"), inspect(r)
    refute contains?(r[:data], "SEC2"), inspect(r)
    refute contains?(r[:data], "Zsecret"), inspect(r)
  end

  # D7 -------------------------------------------------------------------------
  test "D7: :filter errors use the output index after several filtered items" do
    s =
      compile_schema(
        """
        object :hush do
          authorize role(:admin)
          field :id, :id
        end

        object :zsecret do
          authorize role(:admin)
          field :id, :id
        end

        object :pub do
          field :id, :id
        end

        union :any do
          types [:hush, :zsecret, :pub]
          resolve_type fn %{k: k}, _ -> k end
        end

        query do
          field :items, list_of(:any) do
            list_policy :filter
            resolve fn _, _ ->
              {:ok, [%{k: :hush, id: "h1"}, %{k: :hush, id: "h2"}, %{k: :zsecret, id: "s1"},
                     %{k: :pub, id: "p1"}, %{k: :zsecret, id: "s2"}]}
            end
          end
        end
        """,
        "authorizer: Warden.ConfirmProbe.FilterAuthz"
      )

    r = go(s, "{ items { ... on Pub { id } } }", viewer_u())
    assert r.data == %{"items" => [nil, %{"id" => "p1"}, nil]}, inspect(r)

    assert r.errors |> Enum.map(& &1.path) |> Enum.sort() == [["items", 0], ["items", 2]],
           inspect(r)
  end

  # D8 -------------------------------------------------------------------------
  @sub_schema """
  object :doc do
    field :id, :id
    field :body, :string do
      authorize role(:admin)
    end
  end

  query do
    field :ok, :string
  end

  subscription do
    field :feed, :doc do
      config fn _, _ -> {:ok, topic: "zzfeed", context_id: "global"} end
    end

    field :feed_map, :doc do
      config fn _, _ -> {:ok, %{topic: "zzfeedm", context_id: "global"}} end
    end
  end
  """

  defp sub(schema, doc, user) do
    ctx = %{pubsub: Pubsub, current_user: user}

    case Absinthe.run(doc, schema, context: ctx) do
      {:ok, %{"subscribed" => topic}} ->
        :ok = Pubsub.subscribe(topic)
        {:ok, topic}

      {:ok, %{errors: errors}} ->
        {:error, errors}
    end
  end

  defp recv(topic) do
    receive do
      {:subscription_data, ^topic, data} -> data
    after
      1000 -> flunk("no data for #{topic}")
    end
  end

  test "D8: default authorizer drops a user context_id (keyword and map config)" do
    s = compile_schema(@sub_schema, @pa)
    {:ok, a} = sub(s, "subscription { feed { id body } }", admin_u())
    {:ok, v} = sub(s, "subscription { feed { id body } }", viewer_u())
    {:ok, v2} = sub(s, "subscription { feed { id body } }", viewer_u())
    assert length(Enum.uniq([a, v, v2])) == 3
    refute a =~ "global"
    {:ok, am} = sub(s, "subscription { feedMap { id body } }", admin_u())
    {:ok, vm} = sub(s, "subscription { feedMap { id body } }", viewer_u())
    assert am != vm
    refute am =~ "global"

    :ok = Absinthe.Subscription.publish(Pubsub, %{id: "d1", body: "TOP"}, feed: "zzfeed")
    assert recv(a).data == %{"feed" => %{"id" => "d1", "body" => "TOP"}}
    refute contains?(recv(v), "TOP")
  end

  test "D8: actor_key/2 returning nil opts out" do
    s = compile_schema(@sub_schema, "authorizer: Warden.ConfirmProbe.NilKeyAuthz")
    {:ok, a} = sub(s, "subscription { feed { id } }", admin_u())
    {:ok, b} = sub(s, "subscription { feed { id } }", admin_u())
    assert a != b
    refute a =~ "global"
  end

  # D9 -------------------------------------------------------------------------
  test "D9: abstract and wrapped return types with value-independent member rules" do
    s =
      compile_schema(
        """
        interface :thing do
          field :id, :id
          resolve_type fn _, _ -> :a end
        end

        object :a do
          interface :thing
          authorize role(:admin)
          field :id, :id
        end

        object :b do
          interface :thing
          authorize deny()
          field :id, :id
        end

        object :c do
          authorize any_of([role(:admin), check(:self)])
          field :id, :id
        end

        union :ab do
          types [:a, :b]
          resolve_type fn _, _ -> :a end
        end

        union :ac do
          types [:a, :c]
          resolve_type fn _, _ -> :c end
        end

        query do
          field :ok, :string
        end

        subscription do
          field :iface, :thing do
            config fn _, _ -> {:ok, topic: "zz9"} end
          end

          field :wrapped, non_null(list_of(non_null(:a))) do
            config fn _, _ -> {:ok, topic: "zz9"} end
          end

          field :uni, :ab do
            config fn _, _ -> {:ok, topic: "zz9"} end
          end

          field :mixed, :ac do
            config fn _, _ -> {:ok, topic: "zz9"} end
          end
        end
        """,
        @pa
      )

    assert {:error, [_ | _]} = sub(s, "subscription { iface { id } }", viewer_u())
    assert {:error, [_ | _]} = sub(s, "subscription { wrapped { id } }", viewer_u())
    assert {:error, [_ | _]} = sub(s, "subscription { uni { __typename } }", viewer_u())
    assert {:ok, _} = sub(s, "subscription { mixed { __typename } }", viewer_u())
    assert {:ok, _} = sub(s, "subscription { iface { id } }", admin_u())
  end

  # D10 ------------------------------------------------------------------------
  test "D10: false is anonymous; :error and {:error, _} raise, also at subscribe" do
    s =
      compile_schema(
        """
        query do
          field :authed, :string do
            authorize authenticated()
            resolve fn _, _ -> {:ok, "AUTHED"} end
          end
        end

        subscription do
          field :feed, :string do
            authorize authenticated()
            config fn _, _ -> {:ok, topic: "zz10"} end
          end
        end
        """,
        @pa
      )

    r = go(s, "{ authed }", nil, ctx: %{subj: false})
    refute contains?(r[:data], "AUTHED")

    assert_raise Warden.PolicyError, fn -> go(s, "{ authed }", nil, ctx: %{subj: :error}) end

    assert_raise Warden.PolicyError, fn ->
      go(s, "{ authed }", nil, ctx: %{subj: {:error, :x}})
    end

    assert_raise Warden.PolicyError, fn ->
      Absinthe.run("subscription { feed }", s, context: %{pubsub: Pubsub, subj: {:error, :boom}})
    end
  end

  # D11 ------------------------------------------------------------------------
  test "D11: default object denial is null without an error; field and arg denials keep Forbidden" do
    s =
      compile_schema(
        """
        object :zsecret do
          authorize role(:admin)
          field :id, :id
        end

        query do
          field :sec, :zsecret, resolve: fn _, _ -> {:ok, %{id: "S"}} end
          field :secs, list_of(:zsecret), resolve: fn _, _ -> {:ok, [%{id: "S"}]} end
          field :fld, :string do
            authorize role(:admin)
            resolve fn _, _ -> {:ok, "F"} end
          end
          field :argd, :string do
            arg :x, :boolean
            authorize_args x: role(:admin)
            resolve fn _, _ -> {:ok, "A"} end
          end
        end
        """,
        @pa
      )

    r = go(s, "{ sec { id } secs { id } }", viewer_u())
    assert r == %{data: %{"sec" => nil, "secs" => [nil]}}, inspect(r)

    r = go(s, "{ fld argd(x: true) }", viewer_u())
    assert r.data == %{"fld" => nil, "argd" => nil}
    assert Enum.map(r.errors, & &1.message) == ["Forbidden", "Forbidden"]
  end

  # D12 ------------------------------------------------------------------------
  test "D12: list and interface return types warn; root rule or arg rule silences" do
    name = unique("Warden.ConfirmProbe.Mut")

    out =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        Code.compile_string("""
        defmodule #{name} do
          use Absinthe.Schema
          use Warden.Schema, authorizer: Warden.ConfirmProbe.Authz

          object :vault do
            authorize role(:admin)
            field :id, :id
          end

          query do
            field :ok, :string
          end

          mutation do
            field :list_mut, list_of(non_null(:vault)) do
              resolve fn _, _ -> {:ok, []} end
            end

            field :field_guarded, :vault do
              authorize role(:admin)
              resolve fn _, _ -> {:ok, nil} end
            end
          end
        end
        """)
      end)

    assert out =~ ~s(mutation "list_mut")
    refute out =~ "field_guarded"
  end

  # D13 ------------------------------------------------------------------------
  defmodule SDL do
    use Absinthe.Schema
    use Warden.Schema, authorizer: Warden.ConfirmProbe.Authz

    alias Absinthe.Blueprint.Schema.{FieldDefinition, InputValueDefinition}

    import_sdl """
    type Query {
      salary(raw: Boolean, other: Boolean): String
    }
    """

    def hydrate(%InputValueDefinition{identifier: :raw}, [
          %FieldDefinition{identifier: :salary} | _
        ]) do
      [Warden.Hydrate.meta(rule: role(:admin)), {:meta, [cache: false]}]
    end

    def hydrate(%InputValueDefinition{identifier: :other}, [
          %FieldDefinition{identifier: :salary} | _
        ]) do
      [{:meta, [cache: false]}, Warden.Hydrate.meta(rule: role(:admin)), {:meta, [x: 1]}]
    end

    def hydrate(%FieldDefinition{identifier: :salary}, _), do: [{:resolve, &__MODULE__.salary/3}]
    def hydrate(_, _), do: []

    def salary(_, args, _), do: {:ok, "SAL:" <> inspect(args)}
  end

  test "D13: hydrate arg rule survives later {:meta, _}, explicit null restricted" do
    r = go(SDL, "{ salary(raw: true) }", viewer_u())
    refute contains?(r[:data], "SAL:%{raw: true}"), inspect(r)
    r = go(SDL, "{ salary(raw: null) }", viewer_u())
    refute contains?(r[:data], "SAL:%{raw: nil}"), inspect(r)
    r = go(SDL, "{ salary(other: true) }", viewer_u())
    refute contains?(r[:data], "SAL:%{other: true}"), inspect(r)
    assert go(SDL, "{ salary }", viewer_u()).data == %{"salary" => "SAL:%{}"}
  end

  # D14 / D15 ---------------------------------------------------------------------
  defmodule Grid do
    use Absinthe.Schema
    use Warden.Schema, authorizer: Warden.Test.Authz

    # Warden.Plugin deliberately first.
    def plugins, do: [Warden.Plugin, Absinthe.Middleware.Async, Absinthe.Middleware.Batch]

    object :cell do
      field :id, :id

      field :hidden, non_null(:string) do
        authorize role(:admin)
      end
    end

    object :zsecret do
      authorize role(:admin)
      field :id, :id
    end

    query do
      field :deep, list_of(list_of(list_of(:cell))) do
        resolve fn _, _ -> {:ok, [[[%{id: "c1", hidden: "H"}, %{id: "c2", hidden: "H"}]]]} end
      end

      field :chain, list_of(non_null(list_of(non_null(list_of(:cell))))) do
        resolve fn _, _ -> {:ok, [[[%{id: "c3", hidden: "H"}]]]} end
      end

      field :chain2, list_of(non_null(list_of(non_null(:cell)))) do
        resolve fn _, _ -> {:ok, [[%{id: "c4", hidden: "H"}, %{id: "c5", hidden: "H"}]]} end
      end

      field :asecrets, list_of(list_of(:zsecret)) do
        resolve fn _, _, _ ->
          Absinthe.Resolution.Helpers.async(fn -> {:ok, [[%{id: "s1"}]]} end)
        end
      end

      field :plain, :string, resolve: fn _, _ -> {:ok, "plain"} end
    end
  end

  test "D15: three nested nullable list levels, and non-null chains through lists" do
    r = go(Grid, "{ deep { id hidden } }", viewer())
    assert r.data == %{"deep" => [[[nil, nil]]]}, inspect(r)

    r = go(Grid, "{ chain { id hidden } }", viewer())
    assert r.data == %{"chain" => [[[nil]]]}, inspect(r)

    r = go(Grid, "{ chain2 { x: id hidden } }", viewer())
    assert r.data == %{"chain2" => nil}, inspect(r)
  end

  defp batch(schema, docs, user) do
    ctx = %{current_user: user, test_pid: self()}

    pipeline =
      schema
      |> Absinthe.Pipeline.for_document(context: ctx)
      |> Absinthe.Pipeline.before(Absinthe.Phase.Document.Execution.Resolution)

    bps =
      for doc <- docs do
        {:ok, bp, _} = Absinthe.Pipeline.run(doc, pipeline)
        bp
      end

    task = Task.async(fn -> Absinthe.Pipeline.BatchResolver.run(bps, schema: schema) end)

    case Task.yield(task, 3_000) || Task.shutdown(task, :brutal_kill) do
      {:ok, results} ->
        for bp <- results do
          {:ok, bp, _} = Absinthe.Pipeline.run(bp, [Absinthe.Phase.Document.Result])
          bp.result
        end

      nil ->
        :timeout
    end
  end

  test "D14: Warden.Plugin first in a user plugins/0 with async: no loop" do
    r = go(Grid, "{ asecrets { id } deep { hidden } }", viewer())
    assert r.data["asecrets"] == [[nil]]
    out = batch(Grid, ["{ asecrets { id } }", "{ deep { id hidden } }"], viewer())
    assert out != :timeout
  end

  test "D14/D15: in a batch, the second document's fold is not lost" do
    out = batch(Grid, ["{ plain }", "{ chain2 { id hidden } }"], viewer())
    assert out != :timeout
    [_, second] = out
    assert second.data == %{"chain2" => nil}, inspect(second)
  end

  test "D14/D15: in a batch, a fold in each document" do
    out = batch(Grid, ["{ chain2 { id hidden } }", "{ chain2 { id hidden } }"], viewer())
    [first, second] = out
    assert first.data == %{"chain2" => nil}, inspect(first)
    assert second.data == %{"chain2" => nil}, inspect(second)
  end

  test "D15: a fold reached through an aliased fragment in a nested list" do
    r = go(Grid, "{ c: chain2 { ...F } } fragment F on Cell { i: id h: hidden }", viewer())
    assert r.data == %{"c" => nil}, inspect(r)
  end
end
