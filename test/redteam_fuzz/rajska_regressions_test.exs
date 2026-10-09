defmodule Warden.RedteamFuzz.RajskaRegressionsTest do
  @moduledoc """
  The holes an audit found in Rajska, ported to Warden. Every test asserts the SECURE
  behaviour and fails if Warden has the hole.
  """
  # Not async: subscriptions share the test Pubsub registry, and the denial handler
  # mode lives in the process dictionary.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Warden.Test.RF.Data
  alias Warden.Test.Pubsub

  @schema Warden.Test.RF.Schema

  setup do
    Process.delete(:rf_deny_mode)
    :ok
  end

  defp admin, do: Data.user("u1", [:admin])
  defp member, do: Data.user("u1", [:member])

  defp run(doc, user, opts \\ []) do
    context =
      Map.merge(%{user: user, test_pid: self()}, Keyword.get(opts, :context, %{}))

    run_opts =
      [context: context, variables: Keyword.get(opts, :variables, %{})] ++
        Keyword.take(opts, [:pipeline_modifier])

    {:ok, result} = Absinthe.run(doc, Keyword.get(opts, :schema, @schema), run_opts)
    result
  end

  defp hits do
    receive do
      {:rf_hit, tag} -> [tag | hits()]
    after
      0 -> []
    end
  end

  defp contains?(data, needle) when is_binary(data), do: String.contains?(data, needle)

  defp contains?(data, needle) when is_map(data),
    do: Enum.any?(data, fn {_, v} -> contains?(v, needle) end)

  defp contains?(data, needle) when is_list(data), do: Enum.any?(data, &contains?(&1, needle))

  defp contains?(data, needle) when is_atom(data) and not is_nil(data),
    do: contains?(Atom.to_string(data), needle)

  defp contains?(_, _), do: false

  ## ------------------------------------------------------------------
  ## 1. Subscriptions
  ## ------------------------------------------------------------------

  describe "1. subscriptions" do
    defp subscribe(doc, user, extra \\ %{}) do
      context = Map.merge(%{pubsub: Pubsub, user: user, test_pid: self()}, extra)

      case Absinthe.run(doc, @schema, context: context) do
        {:ok, %{"subscribed" => topic}} ->
          :ok = Pubsub.subscribe(topic)
          {:ok, topic}

        {:ok, %{errors: errors}} ->
          {:error, errors}
      end
    end

    defp receive_data(topic) do
      receive do
        {:subscription_data, ^topic, data} -> data
      after
        1000 -> flunk("no data published to #{topic}")
      end
    end

    defp cleanup(topics) do
      for topic <- Enum.uniq(topics) do
        Registry.unregister(Pubsub.Topics, topic)
        Absinthe.Subscription.unsubscribe(Pubsub, topic)
      end
    end

    test "a subscription denied by its field rule cannot subscribe at all" do
      assert {:error, [error]} = subscribe("subscription { adminFeed }", member())
      assert error.message == "Forbidden"
      assert {:error, _} = subscribe("subscription { adminFeed }", nil)
      assert {:ok, topic} = subscribe("subscription { adminFeed }", admin())
      cleanup([topic])
    end

    test "object rules run on every publish, with the subscriber's actor" do
      # Decision 9: SecretDoc's rule (role(:admin)) does not depend on the payload, so a
      # member could never see an event: the subscription is refused up front.
      assert {:error, [%{message: "Forbidden"}]} =
               subscribe("subscription { docChanged { id body } }", member())

      {:ok, admin_topic} = subscribe("subscription { docChanged { id body } }", admin())

      :ok = Absinthe.Subscription.publish(Pubsub, Data.doc("s1"), doc_changed: "rf_docs")

      assert receive_data(admin_topic).data == %{
               "docChanged" => %{"id" => "s1", "body" => "TOPSECRET-s1"}
             }

      cleanup([admin_topic])
    end

    test "a value-dependent return-type rule subscribes, then delivers null per subscriber" do
      # Account: any_of([role(:admin), check(:self)]). The check needs the payload, so
      # both members may subscribe; each publish is checked per subscriber.
      doc = "subscription { accountChanged { id email } }"
      {:ok, alice} = subscribe(doc, Data.user("u1", [:member]))
      {:ok, bob} = subscribe(doc, Data.user("u2", [:member]))

      :ok =
        Absinthe.Subscription.publish(Pubsub, Data.account("a1"), account_changed: "rf_accounts")

      assert receive_data(alice).data == %{
               "accountChanged" => %{"id" => "a1", "email" => "alice@secret.example"}
             }

      bob_data = receive_data(bob)
      assert bob_data.data == %{"accountChanged" => nil}
      refute contains?(bob_data, "alice@secret.example")
      cleanup([alice, bob])
    end

    test "shared context_id: different users never share one resolution" do
      doc = "subscription { accountChanged { id email } }"
      {:ok, alice} = subscribe(doc, Data.user("u1", [:member]))
      {:ok, bob} = subscribe(doc, Data.user("u2", [:member]))
      assert alice != bob

      :ok =
        Absinthe.Subscription.publish(Pubsub, Data.account("a1"), account_changed: "rf_accounts")

      assert receive_data(alice).data == %{
               "accountChanged" => %{"id" => "a1", "email" => "alice@secret.example"}
             }

      assert receive_data(bob).data == %{"accountChanged" => nil}
      cleanup([alice, bob])
    end

    test "shared context_id: a check that reads the context is not resolved with another subscriber's context" do
      # The same user, same roles, in two tenants (two sessions). The object rule is a
      # check that reads `context[:tenant]`, which Warden passes to checks.
      doc = "subscription { tenantDocChanged { id body } }"
      user = Data.user("u1", [:member])
      {:ok, t1} = subscribe(doc, user, %{tenant: "t1"})
      {:ok, t2} = subscribe(doc, user, %{tenant: "t2"})

      :ok =
        Absinthe.Subscription.publish(Pubsub, Data.tenant_doc("t1"),
          tenant_doc_changed: "rf_tenant"
        )

      t1_data = receive_data(t1)
      t2_data = if t1 == t2, do: t1_data, else: receive_data(t2)
      cleanup([t1, t2])

      assert t1_data.data == %{
               "tenantDocChanged" => %{"id" => "td-t1", "body" => "TENANT-SECRET-t1"}
             }

      refute contains?(t2_data.data, "TENANT-SECRET-t1"),
             "the tenant t2 subscriber received tenant t1's document (shared topic: #{t1 == t2})"
    end
  end

  ## ------------------------------------------------------------------
  ## 2 and 3. Abstract types: rules of the concrete type always apply
  ## ------------------------------------------------------------------

  describe "2. object rules read from the concrete type, not the declared abstract type" do
    test "node(id:) returning a restricted type through an interface without a rule" do
      result = run(~s|{ node(id: "s1") { id __typename ... on SecretDoc { body } } }|, member())
      assert result.data == %{"node" => nil}
      refute contains?(result, "SecretDoc")

      assert run(~s|{ node(id: "s1") { id } }|, admin()).data == %{"node" => %{"id" => "s1"}}
    end

    test "an interface with an explicitly public() rule does not weaken the implementor" do
      result = run(~s|{ weak(id: "s1") { body __typename } }|, member())
      assert result.data == %{"weak" => nil}
      refute contains?(result, "TOPSECRET")
    end

    test "anonymous actors get the same treatment" do
      result = run(~s|{ node(id: "s1") { id } weak(id: "s1") { body } }|, nil)
      assert result.data == %{"node" => nil, "weak" => nil}
    end
  end

  describe "3. interface-typed fields without a fragment on the concrete type" do
    test "a list of an interface: restricted items are null, without any fragment" do
      result = run("{ nodes { id } weaks { body } }", member())

      assert result.data == %{
               "nodes" => [nil, %{"id" => "p1"}],
               "weaks" => [nil, %{"body" => "public-p1"}]
             }

      refute contains?(result, "TOPSECRET")
    end

    test "__typename through the interface does not reveal the restricted type" do
      result = run("{ nodes { __typename } }", member())
      assert result.data == %{"nodes" => [nil, %{"__typename" => "PublicDoc"}]}
    end
  end

  ## ------------------------------------------------------------------
  ## 4. Field identifiers that equal root or introspection identifiers
  ## ------------------------------------------------------------------

  describe "4. user fields named like root or introspection identifiers" do
    # Compiles a schema with a `deny()` field under `ident` (optionally with an explicit
    # GraphQL name) on the query root and on a nested object, and with a restricted
    # object type behind a second such field. Returns {:ok, module} or {:compile_error, e}.
    defp ident_schema(ident, name) do
      mod =
        Module.concat(Warden.RedteamFuzz.IdentSchemas, "S#{System.unique_integer([:positive])}")

      peek_ident = String.to_atom("#{ident}_peek")
      peek_name = name && "#{name}_peek"
      name_attrs = if name, do: [name: name], else: []
      peek_attrs = if peek_name, do: [name: peek_name], else: []

      quoted =
        quote do
          defmodule unquote(mod) do
            use Absinthe.Schema
            use Warden.Absinthe, authorizer: Warden.Test.RF.Authz

            object :secret_box do
              authorize role(:admin)
              field :code, :string
            end

            object :holder do
              field unquote(ident), :string, unquote(name_attrs) do
                authorize deny()
                resolve Warden.Test.RF.Resolvers.string({:nested, unquote(ident)})
              end
            end

            query do
              field unquote(ident), :string, unquote(name_attrs) do
                authorize deny()
                resolve Warden.Test.RF.Resolvers.string({:root, unquote(ident)})
              end

              field unquote(peek_ident), :secret_box, unquote(peek_attrs) do
                resolve fn _, _, _ -> {:ok, %{code: "BOXCODE"}} end
              end

              field :holder, :holder, resolve: fn _, _, _ -> {:ok, %{}} end
            end
          end
        end

      try do
        Code.compile_quoted(quoted)
        {:ok, mod}
      rescue
        e -> {:compile_error, e}
      end
    end

    for {ident, name} <- [
          {:subscription, nil},
          {:query, nil},
          {:mutation, nil},
          {:query_type, nil},
          {:schema, nil},
          {:__hidden, "hidden"},
          {:__type, "type_leak"},
          {:__schema, "schema_leak"},
          {:__typename, "typename_leak"}
        ] do
      @ident ident
      @name name
      test "a deny() field with identifier #{inspect(ident)}#{if name, do: " (GraphQL name #{name})"} is enforced" do
        case ident_schema(@ident, @name) do
          {:compile_error, e} ->
            # Rejected at compile time: the schema cannot be built, so it cannot leak.
            IO.puts(
              "[redteam_fuzz] #{inspect(@ident)} rejected at compile time: #{Exception.message(e) |> String.replace("\n", " ") |> String.slice(0, 400)}"
            )

            assert Exception.message(e) =~ "not unique"

          {:ok, schema} ->
            gql = Absinthe.Utils.camelize(@name || Atom.to_string(@ident), lower: true)
            peek = "#{gql}Peek"
            doc = "{ #{gql} holder { #{gql} } #{peek} { code __typename } }"
            result = run(doc, admin(), schema: schema)
            ran = hits()

            assert Map.get(result, :data) != nil, inspect(result)
            refute contains?(result.data, "ran:"), "a deny() field resolved: #{inspect(result)}"
            assert ran == [], "a deny() field's resolver ran: #{inspect(ran)}"

            member_result = run(doc, member(), schema: schema)

            refute contains?(member_result.data, "BOXCODE"),
                   "restricted object behind #{peek} leaked: #{inspect(member_result)}"

            assert get_in(member_result.data, [peek]) == nil,
                   "restricted object behind #{peek} exists: #{inspect(member_result)}"
        end
      end
    end
  end

  ## ------------------------------------------------------------------
  ## 5. Enforcement does not depend on the document pipeline
  ## ------------------------------------------------------------------

  describe "5. enforcement is independent of the document pipeline" do
    @denied_doc ~s|{ node(id: "s1") { id ... on SecretDoc { body } } guardedWrite mw3Closure }|

    defp assert_denied(result) do
      ran = hits()
      refute contains?(result, "TOPSECRET"), inspect(result)
      refute contains?(result, "ran:"), inspect(result)
      assert ran == [{:doc, "s1"}], "unexpected resolvers or writes ran: #{inspect(ran)}"
      assert result.data == %{"node" => nil, "guardedWrite" => nil, "mw3Closure" => nil}
    end

    defp phase_module({mod, _opts}), do: mod
    defp phase_module(mod), do: mod

    test "Absinthe.run with the default pipeline" do
      assert_denied(run(@denied_doc, member()))
    end

    test "Absinthe.run with a pipeline_modifier that drops validation, complexity and telemetry" do
      modifier = fn pipeline, _opts ->
        Enum.reject(pipeline, fn phase ->
          name = inspect(phase_module(phase))

          String.contains?(name, "Validation") or String.contains?(name, "Complexity") or
            String.contains?(name, "Telemetry") or String.contains?(name, "SubscribeSelf")
        end)
      end

      assert_denied(run(@denied_doc, member(), pipeline_modifier: modifier))
    end

    test "a hand-built minimal pipeline" do
      opts = [context: %{user: member(), test_pid: self()}, variables: %{}]
      full = Absinthe.Pipeline.for_document(@schema, opts)

      keep = [
        Absinthe.Phase.Init,
        Absinthe.Phase.Parse,
        Absinthe.Phase.Blueprint,
        Absinthe.Phase.Document.CurrentOperation,
        Absinthe.Phase.Document.Context,
        Absinthe.Phase.Document.Variables,
        Absinthe.Phase.Document.Arguments.Normalize,
        Absinthe.Phase.Schema,
        Absinthe.Phase.Document.Arguments.CoerceEnums,
        Absinthe.Phase.Document.Arguments.CoerceLists,
        Absinthe.Phase.Document.Arguments.Parse,
        Absinthe.Phase.Document.Arguments.Data,
        Absinthe.Phase.Document.Directives,
        Absinthe.Phase.Document.Execution.Resolution,
        Absinthe.Phase.Document.Result
      ]

      pipeline = Enum.filter(full, &(phase_module(&1) in keep))
      assert length(pipeline) == length(keep)

      {:ok, %{result: result}, _} = Absinthe.Pipeline.run(@denied_doc, pipeline)
      assert_denied(result)
    end

    test "Absinthe.Pipeline.for_document run by hand" do
      opts = [context: %{user: member(), test_pid: self()}, variables: %{}]
      pipeline = Absinthe.Pipeline.for_document(@schema, opts)
      {:ok, %{result: result}, _} = Absinthe.Pipeline.run(@denied_doc, pipeline)
      assert_denied(result)
    end

    test "a schema compiled with the PersistentTerm schema provider" do
      start_supervised!({Absinthe.Schema, Warden.Test.RF.PersistentSchema})

      result =
        run("{ doc { id body } guardedWrite }", member(), schema: Warden.Test.RF.PersistentSchema)

      ran = hits()
      assert result.data == %{"doc" => nil, "guardedWrite" => nil}
      assert ran == [], inspect(ran)
    end
  end

  ## ------------------------------------------------------------------
  ## 6. Mutations: no side effects when denied
  ## ------------------------------------------------------------------

  describe "6. denied mutations never execute" do
    test "a field rule stops the resolver" do
      result = run(~s|mutation { deleteAccount(id: "a2") }|, member())
      assert result.data == %{"deleteAccount" => nil}
      assert hits() == []
    end

    test "the mutation root type rule stops every mutation for anonymous actors" do
      result =
        run(~s|mutation { archiveAccount(id: "a2") postOnlyMutation(id: "a1") { id } }|, nil)

      assert result.data == %{"archiveAccount" => nil, "postOnlyMutation" => nil}
      assert hits() == []
    end

    test "an argument rule stops the resolver" do
      result = run(~s|mutation { archiveAccount(id: "a2", hard: true) }|, member())
      assert result.data == %{"archiveAccount" => nil}
      assert hits() == []

      result =
        run(~s|mutation($h: Boolean) { archiveAccount(id: "a2", hard: $h) }|, member(),
          variables: %{"h" => nil}
        )

      assert result.data == %{"archiveAccount" => nil}
      assert hits() == []
    end

    test "an input-field rule stops the resolver" do
      result = run(~s|mutation { updateAccount(input: {makeAdmin: true}) { id } }|, member())
      assert result.data == %{"updateAccount" => nil}
      assert hits() == []
    end

    @tag :documented_limit
    test "a mutation protected only by its return type's object rule warns at compile time" do
      # Decision 12: this stays a documented limit (README "Security model and limits"):
      # the object rule nulls the result after the resolver ran. Warden warns at compile
      # time about such mutations. Converted from "does not execute" by agreement.
      name = Warden.Test.CompileHelpers.unique("Warden.RedteamFuzz.PostOnly")

      warning =
        ExUnit.CaptureIO.capture_io(:stderr, fn ->
          Code.compile_string("""
          defmodule #{name} do
            use Absinthe.Schema
            use Warden.Absinthe, authorizer: Warden.Test.Authz

            object :vault do
              authorize role(:admin)
              field :id, :id
            end

            query do
              field :ok, :string
            end

            mutation do
              field :post_only_mutation, :vault do
                resolve fn _, _ -> {:ok, %{id: "v"}} end
              end

              field :guarded_mutation, :vault do
                authorize role(:admin)
                resolve fn _, _ -> {:ok, %{id: "v"}} end
              end
            end
          end
          """)
        end)

      assert warning =~ ~s(mutation "post_only_mutation")
      assert warning =~ "protected only by the object rule of its return type"
      refute warning =~ "guarded_mutation"

      # The result itself is still hidden.
      result = run(~s|mutation { postOnlyMutation(id: "a2") { id email } }|, member())
      assert result.data == %{"postOnlyMutation" => nil}
    end
  end

  ## ------------------------------------------------------------------
  ## 7. Optional scope arguments
  ## ------------------------------------------------------------------

  describe "7. optional scope arguments" do
    test "omitting the scope argument does not list other users' records" do
      for {doc, vars} <- [
            {"{ accounts { id email } }", %{}},
            {"{ accounts(ownerId: null) { id email } }", %{}},
            {"query($o: ID) { accounts(ownerId: $o) { id email } }", %{}},
            {"query($o: ID) { accounts(ownerId: $o) { id email } }", %{"o" => nil}}
          ] do
        result = run(doc, member(), variables: vars)
        refute contains?(result, "bob@secret"), "#{doc}: #{inspect(result)}"
      end
    end

    test "a field-level scope check denies a missing or null argument" do
      for {doc, vars} <- [
            {"{ scopedAccounts { email } }", %{}},
            {"{ scopedAccounts(ownerId: null) { email } }", %{}},
            {"query($o: ID) { scopedAccounts(ownerId: $o) { email } }", %{"o" => nil}},
            {"{ scopedAccounts(ownerId: \"u2\") { email } }", %{}}
          ] do
        result = run(doc, member(), variables: vars)
        assert result.data == %{"scopedAccounts" => nil}, "#{doc}: #{inspect(result)}"
        assert hits() == [], doc
      end

      assert run(~s|{ scopedAccounts(ownerId: "u1") { email } }|, member()).data ==
               %{"scopedAccounts" => [%{"email" => "alice@secret.example"}]}
    end

    test "null for an argument with a non-null default does not pass its rule" do
      for {doc, vars} <- [
            {"{ byStatus(status: null) }", %{}},
            {"{ byStatus(status: DRAFT) }", %{}},
            {"query($s: Status) { byStatus(status: $s) }", %{"s" => nil}},
            {"query($s: Status = DRAFT) { byStatus(status: $s) }", %{}}
          ] do
        result = run(doc, member(), variables: vars)
        assert result.data == %{"byStatus" => nil}, "#{doc}: #{inspect(result)}"
        assert hits() == [], doc
      end

      assert run("{ byStatus }", member()).data == %{"byStatus" => ["listing for :published"]}
    end
  end

  ## ------------------------------------------------------------------
  ## 8. Middleware before the authorization middleware
  ## ------------------------------------------------------------------

  describe "8. middleware placed before authorization does not run first" do
    test "field middleware declared before the resolver" do
      assert run("{ guardedWrite }", member()).data == %{"guardedWrite" => nil}
      assert hits() == []
    end

    test "middleware/3 prepending an escapable middleware" do
      assert run("{ mw3Write }", member()).data == %{"mw3Write" => nil}
      assert hits() == []
    end

    test "middleware/3 prepending a closure (runtime shim)" do
      assert run("{ mw3Closure }", member()).data == %{"mw3Closure" => nil}
      assert hits() == []
    end

    test "control: the same middleware runs for an allowed actor" do
      run("{ guardedWrite mw3Write mw3Closure }", admin())
      ran = hits()
      assert {:write, :field} in ran and {:write, :mw3} in ran and {:write, :closure} in ran
    end
  end

  ## ------------------------------------------------------------------
  ## 9. Union-level rules
  ## ------------------------------------------------------------------

  describe "9. union-level rules" do
    test "a union rule nulls every member, __typename included" do
      result = run("{ search { __typename } }", nil)
      assert result.data == %{"search" => [nil, nil]}
      refute contains?(result, "PublicDoc")
      refute contains?(result, "SecretDoc")
    end

    test "a single union value is null too, even for a member type without its own rule" do
      result = run(~s|{ searchOne(id: "p1") { __typename ... on PublicDoc { body } } }|, nil)
      assert result.data == %{"searchOne" => nil}
    end

    test "the concrete type's rule still applies after the union rule passes" do
      result =
        run(
          "{ search { __typename ... on SecretDoc { body } ... on PublicDoc { body } } }",
          member()
        )

      assert result.data == %{
               "search" => [nil, %{"__typename" => "PublicDoc", "body" => "public-p1"}]
             }
    end
  end

  ## ------------------------------------------------------------------
  ## 10. Existence oracle
  ## ------------------------------------------------------------------

  describe "10. existence oracle" do
    defp strip(result) do
      Map.update(result, :errors, [], fn errors ->
        Enum.map(errors, &Map.delete(&1, :locations))
      end)
    end

    test "default handler: 'exists but denied' and 'not found' are indistinguishable" do
      exists = run(~s|{ account(id: "a2") { id } }|, member())
      missing = run(~s|{ account(id: "nope") { id } }|, member())

      assert strip(exists) == strip(missing),
             "exists: #{inspect(exists)}\nmissing: #{inspect(missing)}"

      exists = run(~s|{ node(id: "s1") { id } }|, member())
      missing = run(~s|{ node(id: "nope") { id } }|, member())

      assert strip(exists) == strip(missing),
             "exists: #{inspect(exists)}\nmissing: #{inspect(missing)}"
    end

    test "a :null handler: 'exists but denied' and 'not found' are indistinguishable" do
      Process.put(:rf_deny_mode, :null)
      exists = run(~s|{ account(id: "a2") { id } node(id: "s1") { id } }|, member())
      missing = run(~s|{ account(id: "nope") { id } node(id: "nope") { id } }|, member())
      assert strip(exists) == strip(missing)
    end
  end

  ## ------------------------------------------------------------------
  ## 11. Arguments in errors and logs
  ## ------------------------------------------------------------------

  describe "11. arguments never appear in errors or logs" do
    @password "hunter2-RF-PASSWORD"

    test "a denied field with a password argument" do
      {result, log} =
        with_log(fn ->
          run(~s|mutation { login(password: "#{@password}") }|, member())
        end)

      assert result.data == %{"login" => nil}
      refute contains?(inspect(result), @password)
      refute String.contains?(log, @password)
    end

    test "a password passed through a variable" do
      {result, log} =
        with_log(fn ->
          run("mutation($p: String!) { login(password: $p) }", member(),
            variables: %{"p" => @password}
          )
        end)

      refute contains?(inspect(result), @password)
      refute String.contains?(log, @password)
    end

    test "a PolicyError raised during a request with a password argument" do
      log =
        capture_log(fn ->
          error =
            assert_raise Warden.PolicyError, fn ->
              run(~s|mutation { loginCheck(password: "#{@password}") }|, member(),
                context: %{check_result: :ok}
              )
            end

          refute String.contains?(Exception.message(error), @password)
          refute String.contains?(Exception.format(:error, error, []), @password)
        end)

      refute String.contains?(log, @password)
      assert hits() == []
    end

    test "logs about unknown roles do not carry arguments" do
      user = Data.user("u1", [:member, :superuser])

      log =
        capture_log(fn ->
          run(~s|mutation { login(password: "#{@password}") }|, user)
        end)

      refute String.contains?(log, @password)
    end

    test "an argument denial on a password-carrying input does not echo it" do
      {result, log} =
        with_log(fn ->
          run(~s|mutation { archiveAccount(id: "#{@password}", hard: true) }|, member())
        end)

      assert result.data == %{"archiveAccount" => nil}
      refute contains?(inspect(result), @password)
      refute String.contains?(log, @password)
    end
  end

  ## ------------------------------------------------------------------
  ## 12. Truthy non-boolean callback returns
  ## ------------------------------------------------------------------

  describe "12. truthy non-boolean callback returns" do
    for value <- [:ok, {:ok, true}, "yes", "true", 1, [], %{}, nil, :true_ish] do
      @value value
      test "check/2 returning #{inspect(value)} does not grant" do
        try do
          result = run("{ configured }", member(), context: %{check_result: @value})
          assert result.data == %{"configured" => nil}
        rescue
          Warden.PolicyError -> :ok
        end

        assert hits() == []
      end
    end

    test "check/2 returning true grants (control)" do
      assert run("{ configured }", member(), context: %{check_result: true}).data ==
               %{"configured" => "ran::configured"}
    end

    for value <- [true, :ok, {:ok, nil}, nil, {:allow, true}] do
      @value value
      test "deny/1 returning #{inspect(value)} does not grant" do
        Process.put(:rf_deny_mode, {:raw, @value})

        try do
          result = run("{ adminOnly }", member())
          assert result.data == %{"adminOnly" => nil}
          refute contains?(result, "ran:")
        rescue
          Warden.PolicyError -> :ok
        end

        assert hits() == []
      end
    end

    test "roles/2 returning a non-list does not grant" do
      user = %{id: "u1", roles: :admin}

      try do
        result = run("{ adminOnly }", user)
        assert result.data == %{"adminOnly" => nil}
      rescue
        Warden.PolicyError -> :ok
      end

      assert hits() == []
    end

    test "subject/1 returning false is not an authenticated subject" do
      result = run("{ whoami }", false)
      assert result.data == %{"whoami" => nil}, inspect(result)
      assert hits() == []
    end
  end

  ## ------------------------------------------------------------------
  ## Other defects found while porting
  ## ------------------------------------------------------------------

  describe "null folding" do
    test "a denied non-null field folds into its parent object inside nested lists" do
      # Note.text is String! with check(:owns); n1 is owned by u2. d1.hits is [[Hit]].
      # Spec: the Note becomes null (its list items are nullable). Warden's design:
      # "A non-null field that becomes null folds to the nearest nullable parent".
      actor = %{id: "u1", roles: [:b], perms: []}

      {:ok, result} =
        Absinthe.run(
          ~s|{ doc(id: "d1") { hits { ... on Note { id text } } } }|,
          Warden.Test.FZ.Schema,
          context: %{actor: actor}
        )

      assert result.data == %{"doc" => %{"hits" => [[%{}, %{}], [nil]]}}, inspect(result)
    end

    test "control: the same fold one list level deep" do
      actor = %{id: "u1", roles: [:b], perms: []}

      {:ok, result} =
        Absinthe.run(
          ~s|{ doc(id: "d1") { related { ... on Note { id text } } } }|,
          Warden.Test.FZ.Schema,
          context: %{actor: actor}
        )

      assert result.data == %{"doc" => %{"related" => [nil, %{}, %{}]}}
    end
  end
end
