defmodule Warden.Property.DecisionReuseTest do
  @moduledoc """
  Differential suite for `decision_reuse:`. Random schemas (object, interface and field
  rules built from every kind of leaf, list policies, nullability) are compiled twice,
  with `decision_reuse: true` and `decision_reuse: false`; random actors (guests, roles,
  permissions, kinds, tenant memberships, bound and unbound credentials) and random data
  (objects shared under many parents, objects of one type with different owners and
  tenants in one list, the same primary key loaded with different fields, values without
  a primary key, nil parents) then run the same documents against both. The responses
  (data and errors), the denials handed to `deny/1` and any raise must be identical,
  and reuse may never ask the authorizer more often.

  The documents reach one object through several parents and paths, read it through an
  interface, list one primary key twice with different fields, change the context (and
  only its Dataloader `:loader`) in the middle of a document, and pass different field
  arguments to the fields that return the same type.

  `WARDEN_REUSE_SCHEMAS` (default 12) and `WARDEN_REUSE_RUNS` (default 300) scale it.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Warden.Test.CompileHelpers
  alias Warden.Test.Reuse.{Issue, Team, User}

  @schemas String.to_integer(System.get_env("WARDEN_REUSE_SCHEMAS", "12"))
  @runs String.to_integer(System.get_env("WARDEN_REUSE_RUNS", "300"))

  # Leaves that read where the object appears (or whose single and list answers come
  # from different callbacks): rules with them are never reused, and are drawn less often
  # so most schemas exercise reuse.
  @field_leaves [
    "check(:single_owns)",
    "check(:peek_field)",
    "check(:peek_args)"
  ]

  @common_leaves [
    "public()",
    "deny()",
    "authenticated()",
    "role(:admin)",
    "role(:member)",
    ~s|permission("read")|,
    "kind([:bot])",
    ~s|credential_scope("read")|,
    "session()",
    "tenant_role(:viewer)",
    "tenant_role(:owner)",
    "check(:owns)",
    "check(:flag_on)",
    "check(:ctx_allows)",
    "check(:sneaky)",
    "check(:loader_peek)",
    "check(:many_owns)"
  ]

  @field_rules [
    nil,
    "public()",
    "role(:admin)",
    "authenticated()",
    "check(:peek_field)",
    "check(:owns)",
    "check(:ctx_allows)"
  ]

  @list_policies [":null_item", ":filter", ":fail_list"]

  @documents [
    "{ issues { id title body team { id name secret } assignee { id name } } }",
    "{ issues { id title bump body team { id name } } }",
    "{ teams { id name issues { id title team { id name secret } } } }",
    ~s|{ a: team(id: "t1") { id secret } b: issue(id: "1") { team { id secret } } teams { id name } }|,
    "{ issuesAlt { id title body team { id } } issues { id title } }",
    "{ nodes { id ... on Issue { title team { name } } ... on Team { name secret } } }",
    "{ blobs { label secret } issues { id assignee { id name } } }",
    ~s|{ x: issues(tag: "x") { id title } y: issues(tag: "hidden") { id title body } }|,
    "{ teams { id issues { id team { id issues { id title } } } } }",
    "{ mixed { id title body team { id name } } }",
    "{ issues { id bump team { id name } } teams { id name } }",
    "{ issues { id touch title team { id name secret } } teams { id name } }"
  ]

  setup_all do
    seed = ExUnit.configuration()[:seed]
    _state = :rand.seed(:exsss, {seed, 1_847, 31})
    pairs = Enum.map(1..@schemas, fn _index -> compile_pair(random_schema()) end)
    %{pairs: List.to_tuple(pairs)}
  end

  property "decisions with reuse equal decisions without it", %{pairs: pairs} do
    totals = :counters.new(3, [])

    check all(
            index <- integer(0..(tuple_size(pairs) - 1)),
            document <- member_of(@documents),
            data <- data(),
            actor <- actor(),
            context <- context(),
            max_runs: @runs
          ) do
      {reused, plain} = elem(pairs, index)
      context = Map.merge(context, %{data: data, current_user: actor.user})
      context = Map.put(context, :credential, actor.credential)

      {reused_result, reused_denials, reused_calls} = run(document, reused, context)
      {plain_result, plain_denials, plain_calls} = run(document, plain, context)

      assert reused_result == plain_result
      assert reused_denials == plain_denials
      assert reused_calls <= plain_calls

      :counters.add(totals, 1, 1)
      :counters.add(totals, 2, reused_calls)
      :counters.add(totals, 3, plain_calls)
    end

    IO.puts(
      "\n[decision_reuse] #{tuple_size(pairs)} schema pairs, #{:counters.get(totals, 1)} " <>
        "documents: #{:counters.get(totals, 2)} authorizer calls with reuse, " <>
        "#{:counters.get(totals, 3)} without"
    )
  end

  defp run(document, schema, context) do
    context = Map.put(context, :test_pid, self())

    result =
      try do
        {:ok, result} = Absinthe.run(document, schema, context: context)
        result
      rescue
        exception -> {:raised, exception.__struct__, Exception.message(exception)}
      end

    {denials, calls} = drain([], 0)
    {result, denials, calls}
  end

  defp drain(denials, calls) do
    receive do
      {:denial, denial} -> drain([denial | denials], calls)
      {:tenant_roles, _tenant} -> drain(denials, calls)
      _evaluation -> drain(denials, calls + 1)
    after
      0 -> {Enum.reverse(denials), calls}
    end
  end

  defp compile_pair(body) do
    reused = CompileHelpers.compile_schema(body, "authorizer: Warden.Test.Reuse.Authz")

    plain =
      CompileHelpers.compile_schema(
        body,
        "authorizer: Warden.Test.Reuse.Authz, decision_reuse: false"
      )

    {reused, plain}
  end

  defp random_schema do
    team_rule = object_rule(["can(Warden.Test.Reuse.TeamPolicy, :read)" | @common_leaves])
    issue_rule = object_rule(["can(Warden.Test.Reuse.IssuePolicy, :read)" | @common_leaves])
    user_rule = object_rule(@common_leaves)
    blob_rule = object_rule(@common_leaves)
    node_rule = object_rule(@common_leaves)
    team_type = Enum.random([":team", "non_null(:team)"])
    issue_item = Enum.random([":issue", "non_null(:issue)"])

    """
      interface :node do
        #{node_rule}
        field :id, :id
        resolve_type &Warden.Test.Reuse.Resolvers.node_type/2
      end

      object :team do
        #{team_rule}
        interface :node
        field :id, :id
        field :name, :string
        field :secret, :string do
          #{field_rule()}
        end
        field :issues, list_of(:issue) do
          list_policy #{Enum.random(@list_policies)}
          resolve &Warden.Test.Reuse.Resolvers.team_issues/3
        end
      end

      object :user do
        #{user_rule}
        field :id, :id
        field :name, :string do
          #{field_rule()}
        end
      end

      object :blob do
        #{blob_rule}
        field :label, :string
        field :secret, :string do
          #{field_rule()}
        end
      end

      object :issue do
        #{issue_rule}
        interface :node
        field :id, :id
        field :title, :string
        field :body, :string do
          #{field_rule()}
        end
        field :bump, :string do
          middleware Warden.Test.Reuse.Bump
        end
        field :touch, :string do
          middleware Warden.Test.Reuse.Touch
        end
        field :team, #{team_type}
        field :assignee, :user
      end

      query do
        field :issues, list_of(#{issue_item}) do
          arg :tag, :string
          list_policy #{Enum.random(@list_policies)}
          resolve fn _args, resolution -> {:ok, resolution.context.data.issues} end
        end

        field :issues_alt, list_of(:issue) do
          list_policy #{Enum.random(@list_policies)}
          resolve fn _args, resolution -> {:ok, resolution.context.data.issues_alt} end
        end

        field :mixed, list_of(:issue) do
          list_policy #{Enum.random(@list_policies)}
          resolve fn _args, resolution ->
            {:ok, resolution.context.data.issues ++ resolution.context.data.issues_alt}
          end
        end

        field :teams, list_of(:team) do
          list_policy #{Enum.random(@list_policies)}
          resolve fn _args, resolution -> {:ok, resolution.context.data.teams} end
        end

        field :nodes, list_of(:node) do
          resolve fn _args, resolution ->
            {:ok, resolution.context.data.issues ++ resolution.context.data.teams}
          end
        end

        field :blobs, list_of(:blob) do
          resolve fn _args, resolution -> {:ok, resolution.context.data.blobs} end
        end

        field :team, :team do
          arg :id, :id
          resolve fn %{id: id}, resolution ->
            {:ok, Enum.find(resolution.context.data.teams, &(&1.id == id))}
          end
        end

        field :issue, :issue do
          arg :id, :id
          resolve fn %{id: id}, resolution ->
            {:ok, Enum.find(resolution.context.data.issues, &(to_string(&1.id) == id))}
          end
        end
      end
    """
  end

  defp object_rule(leaves) do
    if :rand.uniform(6) == 1,
      do: "",
      else: "authorize " <> random_rule(leaves, 2)
  end

  defp random_rule(leaves, depth) do
    case :rand.uniform(if depth > 0, do: 6, else: 4) do
      5 -> "all_of([#{random_rules(leaves, depth - 1)}])"
      6 -> "any_of([#{random_rules(leaves, depth - 1)}])"
      _leaf -> random_leaf(leaves)
    end
  end

  defp random_leaf(leaves) do
    if :rand.uniform(6) == 1,
      do: Enum.random(@field_leaves),
      else: Enum.random(leaves)
  end

  defp random_rules(leaves, depth) do
    count = 1 + :rand.uniform(2)
    Enum.map_join(1..count, ", ", fn _index -> random_rule(leaves, depth) end)
  end

  defp field_rule do
    case Enum.random(@field_rules) do
      nil -> ""
      rule -> "authorize " <> rule
    end
  end

  defp data do
    gen all(
          users <- users(),
          teams <- teams(),
          issue_specs <- list_of(issue_spec(), min_length: 1, max_length: 7),
          variants <- list_of(member_of([:same, :copy, :flag, :owner]), length: 7),
          blobs <- list_of(blob(), max_length: 3)
        ) do
      issues =
        issue_specs
        |> Enum.with_index(1)
        |> Enum.map(fn {spec, id} -> issue(spec, id, teams, users) end)

      issues_alt =
        issues
        |> Enum.zip(variants)
        |> Enum.map(fn {issue, variant} -> variant(issue, variant) end)

      %{issues: issues, issues_alt: issues_alt, teams: teams, blobs: blobs}
    end
  end

  defp users do
    gen all(tenants <- list_of(member_of([:a, :b]), length: 3)) do
      tenants
      |> Enum.with_index(1)
      |> Enum.map(fn {tenant, id} -> %User{id: "u#{id}", name: "User #{id}", tenant: tenant} end)
    end
  end

  defp teams do
    gen all(specs <- list_of(team_spec(), length: 3)) do
      specs
      |> Enum.with_index(1)
      |> Enum.map(fn {{owner, tenant, flag}, id} ->
        %Team{
          id: "t#{id}",
          owner_id: owner,
          tenant: tenant,
          flag: flag,
          name: "Team #{id}",
          secret: "team secret #{id}"
        }
      end)
    end
  end

  defp team_spec, do: tuple({owner(), tenant(), boolean()})

  defp issue_spec,
    do: tuple({owner(), tenant(), boolean(), integer(0..3), integer(0..3)})

  defp owner, do: member_of(["u1", "u2", "u3", nil])
  defp tenant, do: member_of([:a, :b, nil])

  defp issue({owner, tenant, flag, team_index, assignee_index}, id, teams, users) do
    %Issue{
      id: id,
      owner_id: owner,
      tenant: tenant,
      flag: flag,
      title: "Issue #{id}",
      body: "issue body #{id}",
      team: Enum.at([nil | teams], team_index),
      assignee: Enum.at([nil | users], assignee_index)
    }
  end

  # The same row loaded again: the same term, an equal copy, or a copy whose fields
  # differ (another flag or owner), as a second query or a partial load would give.
  defp variant(issue, :same), do: issue
  defp variant(issue, :copy), do: struct!(Issue, Map.from_struct(issue))
  defp variant(issue, :flag), do: %{issue | flag: not issue.flag}
  defp variant(issue, :owner), do: %{issue | owner_id: "u1"}

  defp blob do
    gen all(owner <- owner(), tenant <- tenant(), flag <- boolean(), label <- member_of(~w(a b))) do
      %{label: label, owner_id: owner, tenant: tenant, flag: flag, secret: "blob secret"}
    end
  end

  defp actor do
    one_of([
      constant(%{user: nil, credential: nil}),
      gen all(
            id <- member_of(["u1", "u2", "u3"]),
            roles <- list_of(member_of([:admin, :member]), max_length: 2),
            perms <- list_of(constant("read"), max_length: 1),
            kind <- member_of([:user, :bot]),
            memberships <- memberships(),
            credential <- credential()
          ) do
        user = %{
          id: id,
          roles: Enum.uniq(roles),
          perms: perms,
          kind: kind,
          memberships: memberships
        }

        %{user: user, credential: credential}
      end
    ])
  end

  defp memberships do
    gen all(
          a <- list_of(member_of([:owner, :viewer]), max_length: 1),
          b <- list_of(member_of([:owner, :viewer]), max_length: 1)
        ) do
      %{a: a, b: b}
    end
  end

  defp credential do
    one_of([
      constant(nil),
      gen all(
            method <- member_of([:session, :api_key]),
            scopes <- member_of([:all, ["read"], []]),
            tenant <- member_of([nil, :a, :b])
          ) do
        %Warden.Credential{method: method, scopes: scopes, tenant: tenant}
      end
    ])
  end

  defp context do
    gen all(
          allow <- list_of(member_of([1, 2, 3, 4, 5, 6, 7, "t1", "t2", "t3"]), max_length: 6),
          hidden <- list_of(member_of([:body, :secret, :title, :team, :name, :id]), max_length: 2),
          deny_mode <- member_of([:error, :null])
        ) do
      %{allow: Enum.uniq(allow), hidden_fields: Enum.uniq(hidden), deny_mode: deny_mode}
    end
  end
end
