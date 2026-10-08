defmodule Warden.RedteamExec.SubscriptionTest do
  # Red-team: subscriptions. Each test asserts the secure behaviour; a failing test is a
  # bypass. Not async: the Absinthe subscription registry is shared.
  use ExUnit.Case, async: false

  import Warden.RedteamExec.Helpers
  import Warden.Test.CompileHelpers

  alias Warden.RedteamExec.Data

  setup do
    Process.delete(:rx_deny)
    Process.delete(:rx_actor_key)
    :ok
  end

  defp admin(opts \\ []), do: Data.user(:admin, opts)
  defp viewer(opts \\ []), do: Data.user(:viewer, opts)

  describe "subscribe-time denial" do
    test "a denied field rule never runs the user's config (no side effects)" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { rxAdminFeed { id } }", viewer())

      refute_received {:ran, :rx_admin_feed_config}
    end

    test "a denied field rule refuses before a config that returns {:error, _}" do
      assert {:error, [error]} = subscribe("subscription { rxAdminFeedError { id } }", viewer())
      assert error.message == "Forbidden"
    end

    test "a denied field rule refuses before a config that raises" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { rxAdminFeedRaise { id } }", viewer())
    end

    test "a 1-arity config is wrapped too" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { rxOneArity { id } }", viewer())
    end

    test "an aliased denied subscription field is refused" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { x: rxAdminFeed { id } }", viewer())
    end

    test "a denied subscription field reached through a fragment on the root is refused" do
      doc = """
      subscription { ...F }
      fragment F on RootSubscriptionType { rxAdminFeed { id } }
      """

      # Absinthe itself cannot subscribe through a root fragment (it raises in
      # SubscribeSelf); either way the subscription must not be registered.
      outcome =
        try do
          subscribe(doc, viewer())
        rescue
          _ -> :raised
        end

      refute match?({:ok, _}, outcome)
      refute_received {:ran, :rx_admin_feed_config}
    end

    test "a restricted input field inside an input object argument refuses the subscription" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe(
                 "subscription { rxFilteredFeed(filter: {includeHidden: true}) { id } }",
                 viewer()
               )
    end

    test "a restricted input field nested two levels deep, via a variable, refuses" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe(
                 "subscription($f: RxFilter) { rxFilteredFeed(filter: $f) { id } }",
                 viewer(),
                 %{},
                 variables: %{"f" => %{"nested" => %{"nested" => %{"includeHidden" => false}}}}
               )
    end

    test "a restricted input field in a list of input objects refuses" do
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe(
                 "subscription { rxListedFeed(filters: [{term: \"a\"}, {includeHidden: true}]) { id } }",
                 viewer()
               )
    end

    test "the subscription root type rule refuses an anonymous subscriber" do
      schema =
        compile_schema(
          """
          query do
            field :x, :string
          end

          subscription do
            authorize authenticated()

            field :feed, :string do
              config fn _, _ -> {:ok, topic: "rx-root"} end
            end
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )

      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { feed }", nil, %{}, schema: schema)
    end

    test "a subscription field added with import_fields is still checked at subscribe time" do
      schema =
        compile_schema(
          """
          query do
            field :x, :string
          end

          object :extra_subs do
            field :imported_feed, :string do
              authorize role(:admin)
              config fn _, _ -> {:ok, topic: "rx-imp"} end
            end
          end

          subscription do
            import_fields :extra_subs
          end
          """,
          "authorizer: Warden.RedteamExec.Authz"
        )

      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { importedFeed }", viewer(), %{}, schema: schema)
    end

    test "a handler returning {:replace, _} for a subscribe denial still refuses" do
      Process.put(:rx_deny, fn _ -> {:replace, %{id: "fake"}} end)

      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { rxAdminFeed { id } }", viewer())
    end

    test "a handler returning :null for a subscribe denial still refuses" do
      Process.put(:rx_deny, fn _ -> :null end)
      assert {:error, [_]} = subscribe("subscription { rxAdminFeed { id } }", viewer())
    end

    # Event-timing oracle: the return type's object rule can never pass for a viewer
    # (role(:admin), value independent), yet the viewer may subscribe and then gets a
    # null + Forbidden message for every event on the topic.
    test "subscribing to a field whose return type the actor can never see is refused" do
      assert {:error, _} = subscribe("subscription { rxSecretUpdated { id } }", viewer())
    end
  end

  describe "context_id sharing and the actor fingerprint" do
    test "different roles with an integer context_id get different subscription ids" do
      {:ok, a} = subscribe("subscription { rxPostIntCtx { notes } }", admin(id: "a"))
      {:ok, v} = subscribe("subscription { rxPostIntCtx { notes } }", viewer(id: "v"))
      assert a != v
      publish(Data.post(), rx_post_int_ctx: "rx-pi")
      assert receive_data(v).data == %{"rxPostIntCtx" => %{"notes" => nil}}
    end

    test "different roles with an atom context_id get different subscription ids" do
      {:ok, a} = subscribe("subscription { rxPostAtomCtx { notes } }", admin(id: "a"))
      {:ok, v} = subscribe("subscription { rxPostAtomCtx { notes } }", viewer(id: "v"))
      assert a != v
    end

    test "context_id: false is not shared" do
      {:ok, a} = subscribe("subscription { rxPostFalseCtx { notes } }", admin(id: "a"))
      {:ok, v} = subscribe("subscription { rxPostFalseCtx { notes } }", viewer(id: "v"))
      assert a != v
    end

    test "a list of topics with a context_id is fingerprinted" do
      {:ok, a} = subscribe("subscription { rxPostListTopics { notes } }", admin(id: "a"))
      {:ok, v} = subscribe("subscription { rxPostListTopics { notes } }", viewer(id: "v"))
      assert a != v
      publish(Data.post(), rx_post_list_topics: "rx-l2")
      assert receive_data(v).data == %{"rxPostListTopics" => %{"notes" => nil}}
    end

    test "a user-set document_id with a shared context_id does not merge different actors" do
      {:ok, a} = subscribe("subscription { rxPostDocId { notes } }", admin(id: "a"))
      {:ok, v} = subscribe("subscription { rxPostDocId { title } }", viewer(id: "v"))
      assert a != v
    end

    test "same roles, same subject id, different subject attributes read by a check" do
      # Two tenants both have a user with id "u1" (ids are only unique per tenant).
      t1 = Data.user(:viewer, id: "u1", tenant: "acme")
      t2 = Data.user(:viewer, id: "u1", tenant: "globex")

      {:ok, first} = subscribe("subscription { rxTdocUpdated { body } }", t1)
      {:ok, second} = subscribe("subscription { rxTdocUpdated { body } }", t2)

      publish(Data.tdoc("acme"), rx_tdoc_updated: "rx-t")

      first_data = receive_data(first)
      second_data = if first == second, do: first_data, else: receive_data(second)

      assert first_data.data == %{"rxTdocUpdated" => %{"body" => "body-acme"}}
      # The globex user must not see acme's document.
      refute contains?(second_data, "body-acme")
      assert first != second
    end

    test "same subject and roles, different context read by a check (org selected per session)" do
      user = viewer(id: "u1")

      {:ok, first} = subscribe("subscription { rxOdocUpdated { body } }", user, %{org: "acme"})
      {:ok, second} = subscribe("subscription { rxOdocUpdated { body } }", user, %{org: "globex"})

      publish(Data.odoc("acme"), rx_odoc_updated: "rx-o")

      first_data = receive_data(first)
      second_data = if first == second, do: first_data, else: receive_data(second)

      assert first_data.data == %{"rxOdocUpdated" => %{"body" => "body-acme"}}
      refute contains?(second_data, "body-acme")
      assert first != second
    end

    test "a revoked session keeps receiving data through a shared context_id" do
      # roles/2 reads live per-session state from the context, as the README advises.
      {:ok, revoked} = Agent.start_link(fn -> MapSet.new() end)

      roles_fun = fn user, ctx ->
        if MapSet.member?(Agent.get(revoked, & &1), ctx[:session]), do: [], else: user.roles
      end

      user = Data.user(:editor, id: "u1")

      {:ok, live} =
        subscribe("subscription { rxPostShared { notes } }", user, %{
          session: "live",
          roles_fun: roles_fun
        })

      {:ok, stolen} =
        subscribe("subscription { rxPostShared { notes } }", user, %{
          session: "stolen",
          roles_fun: roles_fun
        })

      # The stolen session is revoked; the next event must not reach it with editor data.
      Agent.update(revoked, &MapSet.put(&1, "stolen"))
      publish(Data.post(), rx_post_shared: "rx-p")

      live_data = receive_data(live)
      stolen_data = if live == stolen, do: live_data, else: receive_data(stolen)

      assert live_data.data == %{"rxPostShared" => %{"notes" => "editor-notes"}}
      refute contains?(stolen_data, "editor-notes")
    end

    test "subjects without :id that differ only in a field get different keys" do
      a = %{name: "a", roles: [:viewer]}
      b = %{name: "b", roles: [:viewer]}

      assert Warden.Authorizer.default_actor_key(actor(a)) !=
               Warden.Authorizer.default_actor_key(actor(b))
    end

    test "an actor_key that returns a non-string fails closed at subscribe" do
      Process.put(:rx_actor_key, fn _ -> 123 end)

      assert_raise Warden.PolicyError, fn ->
        subscribe("subscription { rxPostShared { notes } }", viewer())
      end
    end

    test "an actor_key that raises fails closed at subscribe" do
      Process.put(:rx_actor_key, fn _ -> raise "no key" end)

      assert_raise RuntimeError, fn ->
        subscribe("subscription { rxPostShared { notes } }", viewer())
      end
    end

    test "default key: roles listed in a different order or duplicated give the same key, but different roles differ" do
      k1 = Warden.Authorizer.default_actor_key(actor(%{id: 1, roles: [:viewer, :editor]}))
      k2 = Warden.Authorizer.default_actor_key(actor(%{id: 1, roles: [:editor, :editor]}))
      k3 = Warden.Authorizer.default_actor_key(actor(%{id: 1, roles: [:admin]}))
      assert k1 == k2
      assert k1 != k3
    end
  end

  describe "publish time" do
    test "the publisher context is not used: a nested union payload resolves as the subscriber" do
      {:ok, v} = subscribe("subscription { rxResultFeed { ... on RxSecret { code } } }", viewer())
      publish(Data.secret(), rx_result_feed: "rx-r")
      data = receive_data(v)
      refute contains?(data, "ALPHA")
    end

    test "a nested list of denied objects inside the payload is nulled per item" do
      {:ok, v} = subscribe("subscription { rxBoxFeed { secrets { code } } }", viewer())
      publish(%{}, rx_box_feed: "rx-b")
      data = receive_data(v)
      refute contains?(data, "ALPHA")
      refute contains?(data, "BRAVO")
    end

    test "a denied non-null field in the payload folds without leaking siblings" do
      {:ok, v} = subscribe("subscription { rxBoxFeed { label locked } }", viewer())
      publish(%{}, rx_box_feed: "rx-b")
      data = receive_data(v)
      assert data.data == %{"rxBoxFeed" => nil}
    end

    test "a subscriber whose user was deleted (subject now nil at publish) sees nothing protected" do
      {:ok, store} = Agent.start_link(fn -> admin() end)
      ctx = %{subject_fun: fn _ -> Agent.get(store, & &1) end}

      {:ok, t} = subscribe("subscription { rxSecretUpdated { code } }", nil, ctx)
      Agent.update(store, fn _ -> nil end)
      publish(Data.secret(), rx_secret_updated: "rx-s")
      refute contains?(receive_data(t), "ALPHA")
    end

    test "Absinthe.Subscription.publish/3 directly with a bare map payload is still checked" do
      {:ok, t} = subscribe("subscription { rxPostShared { notes title } }", viewer(id: "pv"))
      publish(%{id: "p9", title: "T", notes: "secret-notes"}, rx_post_shared: "rx-p")
      data = receive_data(t)
      refute contains?(data, "secret-notes")
      assert contains?(data, "T")
    end

    test "a denied mutation does not trigger a publish, even through an argument rule" do
      {:ok, t} = subscribe("subscription { rxNuked }", admin())

      result =
        run("mutation { nukeArg(filter: {includeHidden: true}) }", viewer())

      assert result.data == %{"nukeArg" => nil}
      assert ran() == []
      assert receive_data(t, 100) == :none
    end

    test "a denial handler returning {:replace, _} on a mutation neither runs it nor publishes" do
      {:ok, t} = subscribe("subscription { rxNuked }", admin())
      Process.put(:rx_deny, fn _ -> {:replace, true} end)

      run("mutation { nuke }", viewer())
      assert ran() == []
      assert receive_data(t, 100) == :none
    end
  end

  defp actor(subject), do: Warden.Actor.build(Warden.RedteamExec.Authz, %{current_user: subject})
end
