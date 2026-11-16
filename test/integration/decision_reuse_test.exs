defmodule Warden.Absinthe.DecisionReuseTest do
  @moduledoc """
  The cases of `decision_reuse:` that the differential suite
  (`test/property/decision_reuse_test.exs`) does not generate: mutations, a check that
  reads state the document changes, the evaluation counts reuse saves, and the plan and
  options. Each document runs against a schema with and one without reuse, and must give
  the same response and denials.
  """
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers

  alias Warden.Absinthe.Reuse
  alias Warden.Authorizer.Catalog
  alias Warden.Test.Reuse.{Issue, Team, User}

  @shared_body """
    object :team do
      authorize check(:revoked)
      field :id, :id
      field :name, :string
    end

    object :issue do
      authorize check(:owns)
      field :id, :id
      field :title, :string
      field :body, :string do
        authorize role(:admin)
      end
      field :team, :team
      field :assignee, :user
    end

    object :user do
      authorize authenticated()
      field :id, :id
      field :name, :string
    end

    query do
      field :issues, list_of(:issue) do
        resolve fn _args, resolution -> {:ok, resolution.context.issues} end
      end

      field :team, :team do
        arg :id, :id
        resolve fn %{id: id}, resolution ->
          {:ok, Enum.find(resolution.context.teams, &(&1.id == id))}
        end
      end

      field :revoke, :team do
        arg :id, :id
        resolve fn %{id: id}, resolution ->
          Agent.update(resolution.context.revoked, &[id | &1])
          {:ok, Enum.find(resolution.context.teams, &(&1.id == id))}
        end
      end
    end

    mutation do
      field :team_read, :team do
        arg :id, :id
        resolve fn %{id: id}, resolution ->
          {:ok, Enum.find(resolution.context.teams, &(&1.id == id))}
        end
      end

      field :revoke, :team do
        arg :id, :id
        resolve fn %{id: id}, resolution ->
          Agent.update(resolution.context.revoked, &[id | &1])
          {:ok, Enum.find(resolution.context.teams, &(&1.id == id))}
        end
      end
    end
  """

  setup_all do
    reused = compile_schema(@shared_body, "authorizer: Warden.Test.Reuse.Authz")

    plain =
      compile_schema(@shared_body, "authorizer: Warden.Test.Reuse.Authz, decision_reuse: false")

    %{reused: reused, plain: plain}
  end

  defp teams, do: Enum.map(1..10, &%Team{id: "t#{&1}", name: "Team #{&1}", owner_id: "u1"})

  defp issues(teams) do
    Enum.map(1..100, fn id ->
      %Issue{id: id, owner_id: "u1", title: "Issue #{id}", team: Enum.at(teams, rem(id, 10))}
    end)
  end

  defp context(extra) do
    {:ok, revoked} = Agent.start_link(fn -> [] end)
    teams = teams()
    user = %{id: "u1", roles: [], perms: []}

    Map.merge(
      %{
        test_pid: self(),
        revoked: revoked,
        teams: teams,
        issues: issues(teams),
        current_user: user
      },
      extra
    )
  end

  # Runs `document` with and without reuse on a fresh context each; asserts the same
  # response and denials and returns {result, calls with reuse, calls without}.
  defp both(document, schemas, extra \\ %{}) do
    {reused, reused_denials, reused_calls} = run(document, schemas.reused, context(extra))
    {plain, plain_denials, plain_calls} = run(document, schemas.plain, context(extra))
    assert reused == plain
    assert reused_denials == plain_denials
    {reused, reused_calls, plain_calls}
  end

  defp run(document, schema, context) do
    {:ok, result} = Absinthe.run(document, schema, context: context)
    {denials, calls} = drain([], %{})
    {result, denials, calls}
  end

  defp drain(denials, calls) do
    receive do
      {:denial, denial} -> drain([denial | denials], calls)
      {:check, name} -> drain(denials, Map.update(calls, name, 1, &(&1 + 1)))
      _other -> drain(denials, calls)
    after
      0 -> {Enum.reverse(denials), calls}
    end
  end

  describe "a list where many items share one nested object" do
    test "each distinct object rule input is decided once", schemas do
      document = "{ issues { id title body team { id name } assignee { id } } }"
      {result, reused_calls, plain_calls} = both(document, schemas)

      assert Enum.count(result.data["issues"]) == 100
      # Without reuse: the issue rule at the list and again for each of its 4 fields
      # without their own rule plus `body`, and the team rule under each of the 100 issues
      # and again for its 2 fields.
      assert plain_calls == %{owns: 100 * 6, revoked: 100 * 3}
      # With reuse: each issue once, each of the 10 teams once.
      assert reused_calls == %{owns: 100, revoked: 10}
    end
  end

  describe "state the document changes" do
    test "a mutation decides every root field again", schemas do
      document = """
      mutation {
        a: teamRead(id: "t1") { id name }
        b: revoke(id: "t1") { id }
        c: teamRead(id: "t1") { id name }
      }
      """

      {result, _reused_calls, _plain_calls} = both(document, schemas)

      assert result.data == %{"a" => %{"id" => "t1", "name" => "Team 1"}, "b" => nil, "c" => nil}
    end

    test "a context change in the middle of a document decides again" do
      body = """
        object :team do
          authorize check(:ctx_allows)
          field :id, :id
        end

        object :issue do
          authorize check(:owns)
          field :id, :id
          field :bump, :string do
            middleware Warden.Test.Reuse.Bump
          end
          field :team, :team
        end

        query do
          field :issues, list_of(:issue) do
            resolve fn _args, resolution -> {:ok, resolution.context.issues} end
          end
        end
      """

      schemas = %{
        reused: compile_schema(body, "authorizer: Warden.Test.Reuse.Authz"),
        plain: compile_schema(body, "authorizer: Warden.Test.Reuse.Authz, decision_reuse: false")
      }

      team = %Team{id: "t1"}
      issues = Enum.map(1..3, &%Issue{id: &1, owner_id: "u1", team: team})
      document = "{ issues { bump team { id } } }"

      # Every `bump` toggles the team in `allow`: denied under the first issue, allowed
      # under the second, denied under the third.
      {result, _reused_calls, _plain_calls} =
        both(document, schemas, %{issues: issues, allow: ["t1"]})

      assert Enum.map(result.data["issues"], & &1["team"]) == [nil, %{"id" => "t1"}, nil]
    end

    test "an object admitted before a context change is decided again for later fields" do
      body = """
        object :issue do
          authorize check(:ctx_allows)
          field :id, :id
          field :title, :string
          field :bump, :string do
            middleware Warden.Test.Reuse.Bump
          end
        end

        query do
          field :issues, list_of(:issue) do
            resolve fn _args, resolution -> {:ok, resolution.context.issues} end
          end
        end
      """

      schemas = %{
        reused: compile_schema(body, "authorizer: Warden.Test.Reuse.Authz"),
        plain: compile_schema(body, "authorizer: Warden.Test.Reuse.Authz, decision_reuse: false")
      }

      issues = Enum.map(1..2, &%Issue{id: &1, title: "Issue #{&1}"})

      # `bump` drops the issue from `allow`, so its `title` (after `bump`) is denied.
      {result, _reused_calls, _plain_calls} =
        both("{ issues { id bump title } }", schemas, %{issues: issues, allow: [1, 2]})

      assert result.data["issues"] == [
               %{"id" => "1", "bump" => "bumped", "title" => nil},
               %{"id" => "2", "bump" => "bumped", "title" => nil}
             ]
    end

    test "a new Dataloader loader keeps per_object decisions and decides policies again" do
      body = """
        object :team do
          authorize can(Warden.Test.Reuse.TeamPolicy, :read)
          field :id, :id
        end

        object :issue do
          authorize check(:loader_peek)
          field :id, :id
          field :title, :string
          field :touch, :string do
            middleware Warden.Test.Reuse.Touch
          end
          field :team, :team
        end

        query do
          field :issues, list_of(:issue) do
            resolve fn _args, resolution -> {:ok, resolution.context.issues} end
          end
        end
      """

      schemas = %{
        reused: compile_schema(body, "authorizer: Warden.Test.Reuse.Authz"),
        plain: compile_schema(body, "authorizer: Warden.Test.Reuse.Authz, decision_reuse: false")
      }

      team = %Team{id: "t1", flag: true}
      issues = Enum.map(1..3, &%Issue{id: &1, title: "Issue #{&1}", team: team})

      # `touch` sets `:loader` to 1, 2 and 3 under the three issues. The `per_object`
      # check never sees it, so every title shows; the policy reads it and denies at 2.
      {result, reused_calls, plain_calls} =
        both("{ issues { touch title team { id } } }", schemas, %{issues: issues})

      assert result.data["issues"] == [
               %{"touch" => "touched", "title" => "Issue 1", "team" => %{"id" => "t1"}},
               %{"touch" => "touched", "title" => "Issue 2", "team" => nil},
               %{"touch" => "touched", "title" => "Issue 3", "team" => %{"id" => "t1"}}
             ]

      assert reused_calls == %{loader_peek: 3}
      assert plain_calls == %{loader_peek: 3 + 3 * 3}
    end

    test "nothing is kept between executions", schemas do
      context = context(%{})
      {:ok, first} = Absinthe.run(~s|{ team(id: "t2") { id } }|, schemas.reused, context: context)
      Agent.update(context.revoked, &["t2" | &1])

      {:ok, second} =
        Absinthe.run(~s|{ team(id: "t2") { id } }|, schemas.reused, context: context)

      assert first.data == %{"team" => %{"id" => "t2"}}
      assert second.data == %{"team" => nil}
    end
  end

  describe "values" do
    test "a primary key loaded with other fields is decided again" do
      memo = %{entries: %{}}
      issue = %Issue{id: 1, owner_id: "u1"}
      memo = Reuse.store(memo, :issue, {:check, :owns, []}, issue, %{}, :ok)

      assert Reuse.lookup(memo, :issue, {:check, :owns, []}, issue, %{}) == {:ok, :ok}

      assert Reuse.lookup(memo, :issue, {:check, :owns, []}, %{issue | owner_id: "u2"}, %{}) ==
               :miss

      assert Reuse.lookup(memo, :issue, {:check, :flag_on, []}, issue, %{}) == :miss
      assert Reuse.lookup(memo, :team, {:check, :owns, []}, issue, %{}) == :miss
      assert Reuse.lookup(memo, :issue, {:check, :owns, []}, issue, %{allow: [1]}) == :miss
    end

    test "values without a primary key are never stored" do
      memo = Reuse.store(%{entries: %{}}, :blob, :public, %{label: "a"}, nil, :ok)
      assert memo.entries == %{}
      assert Reuse.identity(%User{id: nil}) == :none
      assert Reuse.identity(%{id: 4}) == {:map, 4}
    end

    test "a denial a timeout caused is asked again" do
      unavailable = {:deny, %{reason: :unavailable, trace: []}}
      in_trace = {:deny, %{reason: nil, trace: [{{:check, :slow, []}, {:deny, :unavailable}}]}}
      lasting = {:deny, %{reason: nil, trace: [{{:check, :owns, []}, {:deny, nil}}]}}
      issue = %Issue{id: 1}

      for result <- [unavailable, in_trace] do
        memo = Reuse.store(%{entries: %{}}, :issue, :rule, issue, nil, result)
        assert memo.entries == %{}
      end

      memo = Reuse.store(%{entries: %{}}, :issue, :rule, issue, nil, lasting)
      assert Reuse.lookup(memo, :issue, :rule, issue, nil) == {:ok, lasting}
    end
  end

  describe "the plan" do
    test "only fields without a rule of their own skip the middleware", schemas do
      plan = Warden.Absinthe.plan(schemas.reused)
      {title, _post} = plan.fields[{:issue, :title}]
      {body, _post} = plan.fields[{:issue, :body}]
      {root, _post} = plan.fields[{:query, :issues}] || {nil, nil}

      assert title.parent_only
      assert title.reuse_admissible
      refute Map.has_key?(body, :parent_only)
      assert body.reuse_admissible
      assert root == nil or not Map.has_key?(root, :parent_only)
    end

    test "rules that read the field are never reused" do
      schema =
        compile_schema(
          """
          object :thing do
            authorize any_of([check(:peek_field), role(:admin)])
            field :id, :id
          end

          query do
            field :things, list_of(:thing), resolve: fn _args, _resolution -> {:ok, []} end
          end
          """,
          "authorizer: Warden.Test.Reuse.Authz"
        )

      plan = Warden.Absinthe.plan(schema)
      {pre, _post} = plan.fields[{:thing, :id}]
      {_pre, post} = plan.fields[{:query, :things}]

      refute Map.has_key?(pre, :parent_only)
      refute Map.has_key?(pre, :reuse_admissible)
      assert post.scopes == %{}
    end

    test "decision_reuse: false plans as before", schemas do
      plan = Warden.Absinthe.plan(schemas.plain)
      {title, _post} = plan.fields[{:issue, :title}]
      {_pre, post} = plan.fields[{:query, :issues}]

      refute Map.has_key?(title, :parent_only)
      refute Map.has_key?(title, :reuse_admissible)
      refute Map.has_key?(post, :reuse)
    end

    test "the option and the check option are validated" do
      assert_raise CompileError, ~r/`:decision_reuse` must be true or false/, fn ->
        compile_schema(
          "query do\n field :a, :string\n end",
          "authorizer: Warden.Test.Reuse.Authz, decision_reuse: :yes"
        )
      end

      assert {:error, [message]} =
               Catalog.build(roles: [:admin], checks: [owns: [per_object: 1]])

      assert message =~ "`per_object:` must be a boolean"
    end
  end

  describe "telemetry" do
    test "a field without its own rule on an admitted object emits nothing", schemas do
      handler = "decision-reuse-#{System.unique_integer([:positive])}"
      test_pid = self()

      :telemetry.attach(
        handler,
        [:warden, :decision],
        fn _event, measurements, metadata, _config ->
          send(test_pid, {:decision_event, metadata.kind, measurements.count})
        end,
        nil
      )

      context = context(%{})
      {:ok, _result} = Absinthe.run("{ issues { id title } }", schemas.reused, context: context)
      :telemetry.detach(handler)

      events = for {:decision_event, kind, count} <- drain_events([]), do: {kind, count}
      assert events == [{:object, 100}]
    end
  end

  defp drain_events(acc) do
    receive do
      {:decision_event, _kind, _count} = event -> drain_events([event | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end
