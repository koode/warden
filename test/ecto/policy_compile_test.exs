defmodule Warden.Ecto.PolicyCompileTest do
  # Compile-time errors and checks that need no database.
  use ExUnit.Case, async: true

  import Ecto.Query, only: [from: 1, from: 2, or_where: 2]
  import Warden.Test.CompileHelpers
  import Warden.Test.Ecto.People

  alias Warden.Ecto, as: WardenEcto
  alias Warden.Ecto.Policy.Graph
  alias Warden.Test.Ecto.{Authz, Comment, Issue, Note, Team}

  # Compiles an authorizer and one policy with `opts` and `body`.
  defp policy!(opts, body \\ "allow :read, rule: public()") do
    authorizer = unique("Warden.Test.Compiled.EctoAuthz")
    policy = unique("Warden.Test.Compiled.EctoPolicy")

    compile!("""
    defmodule #{authorizer} do
      use Warden.Authorizer,
        roles: [:admin],
        kinds: [:user, :webhook],
        tenant_roles: [:member],
        policies: [#{policy}]

      def subject(context), do: context[:current_user]
      def roles(_user, _context), do: []
      def tenant_roles(_user, _tenant, _context), do: [:member]
    end

    defmodule #{policy} do
      use Warden.Ecto.Policy, authorizer: #{authorizer}, #{opts}
      #{body}
    end
    """)

    Module.concat([policy])
  end

  @team "schema: Warden.Test.Ecto.Team, as: :team, tenant: :workspace_id, actions: [:read]"
  @issue "schema: Warden.Test.Ecto.Issue, as: :issue, tenant: :workspace_id, actions: [:read]"

  describe "options" do
    test "are validated" do
      for {opts, message} <- [
            {"as: :team, actions: [:read]", ~r/`:schema` \(an Ecto schema module\) is required/},
            {"schema: String, as: :team, actions: [:read]", ~r/String is not an Ecto schema/},
            {"schema: Warden.Test.Ecto.Team, actions: [:read]", ~r/`:as` .* is required/},
            {"schema: Warden.Test.Ecto.Team, as: :team, actions: []", ~r/`:actions` must be/},
            {"schema: Warden.Test.Ecto.Team, as: :team, actions: [:read], tenant: :nope",
             ~r/`:tenant` :nope is not a field/},
            {"#{@team}, tenant: :name", ~r/options given twice: \[:tenant\]/},
            {"schema: Warden.Test.Ecto.Team, as: :team, actions: [:read], null_tenant: true",
             ~r/`:null_tenant` needs a `:tenant` field/},
            {"#{@team}, write_actions: [:write]",
             ~r/`:write_actions` names actions that are not/},
            {"#{@team}, subject_id: \"id\"", ~r/`:subject_id` must be/},
            {"#{@team}, system_kinds: [:robot]", ~r/`:system_kinds` names :robot/},
            {"#{@team}, scope: true", ~r/unknown options: \[:scope\]/}
          ] do
        assert_raise CompileError, message, fn -> policy!(opts) end
      end
    end

    test "the authorizer must list the policy" do
      assert_raise CompileError, ~r/does not list .* in its `policies:`/, fn ->
        compile!("""
        defmodule #{unique("Warden.Test.Compiled.Unlisted")} do
          use Warden.Ecto.Policy, authorizer: Warden.Test.Ecto.Authz, #{@team}
          allow :read, rule: public()
        end
        """)
      end
    end

    test "the schema needs exactly one primary key" do
      schema = unique("Warden.Test.Compiled.Composite")

      compile!("""
      defmodule #{schema} do
        use Ecto.Schema
        @primary_key false
        schema "composite" do
          field :left, :id, primary_key: true
          field :right, :id, primary_key: true
        end
      end
      """)

      assert_raise CompileError, ~r/must have exactly one primary key field/, fn ->
        policy!("schema: #{schema}, as: :row, actions: [:read]")
      end
    end

    test "a valid policy reports its info" do
      policy = policy!(@team <> ", system_kinds: [:webhook]")
      info = policy.__warden_policy__(:info)

      assert %{for: Team, actions: [:read], tenant: :workspace_id, enforces_binding: true} = info
      assert info.system_kinds == [:webhook]
    end
  end

  describe "clauses" do
    test "are validated" do
      for {body, message} <- [
            {"allow :write, rule: public()", ~r/:write is not in `:actions`/},
            {"allow :read, rule: public(), nope: 1", ~r/unknown clause keys: \[:nope\]/},
            {"allow :read, where: [private: false]",
             ~r/an allow clause needs a condition on the actor/},
            {"allow :read, rule: public(), where: [nope: 1]", ~r/`where:` :nope is not a field/},
            {"allow :read, rule: public(), where: [private: \"yes\"]",
             ~r/`where:` "yes" is not a valid :boolean/},
            {"allow :read, rule: public(), where: [name: [\"a\"]]",
             ~r/must be compared with a single literal value/},
            {"allow :read, rule: public(), where: []", ~r/`where:` must be a non-empty keyword/},
            {"allow :read, through: :nope", ~r/`through:` :nope is not an association/},
            {"allow :read, through: :memberships", ~r/must be a belongs_to association/},
            {"allow :read, through: :parent", ~r/`through: :parent` is a cycle/},
            {"allow :read, through_any: :parent", ~r/must be a has_many or many_to_many/},
            {"allow :read, rule: public(), none: :parent",
             ~r/`none: :parent` must be a has_many, has_one or many_to_many/},
            {"allow :read, actor_in: [:nope]", ~r/`actor_in:` :nope is not a field/},
            {"allow :read, actor_in: []", ~r/`actor_in:` must be a non-empty list/},
            {"allow :read, member_of: {Warden.Test.Ecto.TeamMembership, :team_id}",
             ~r/`member_of:` must be \{schema, row_key, actor_key\}/},
            {"allow :read, member_of: {Warden.Test.Ecto.TeamMembership, :team_id, :nope}",
             ~r/`member_of:` :nope is not a field of Warden.Test.Ecto.TeamMembership/},
            {"allow :read, grant: {Warden.Test.Ecto.TeamMembership, :team_id, :user_id, expires_at: :user_id}",
             ~r/`expires_at:` :user_id must be a datetime field/},
            {"allow :read, grant: {Warden.Test.Ecto.TeamMembership, :team_id, :user_id, until: :x}",
             ~r/unknown \[:until\]/},
            {"allow :read, through_type: {:name, :parent_id, %{}}", ~r/`through_type:` must be/},
            {"allow :read, through_type: {:name, :parent_id, %{1 => X}}",
             ~r/1 is not a valid :string for :name/},
            {"allow :read, within: {:team_ids, :nope}", ~r/`within:` :nope is not a field/},
            {"allow :read, rule: public(), if_nil: :tenant",
             ~r/`if_nil:` is an option of `through:`/},
            {"allow :read, rule: can(Warden.Test.Ecto.Issues, :read)",
             ~r/`rule:` cannot use can/},
            {"allow :read, rule: covered()", ~r/`rule:` cannot use covered\(\)/},
            {"allow :read, rule: tenant_role(:member, tenant: {:arg, [:id]})",
             ~r/`rule:` tenant_role\/2 takes the tenant being scoped/},
            {"allow :read, rule: tenant_role(:owner)", ~r/`rule:`.*:owner/},
            {"requires :read, rule: public()", ~r/has requires clauses but no allow clause/},
            {"allow :read, rule: public(), rule: public()", ~r/clause keys given twice/}
          ] do
        assert_raise CompileError, message, fn -> policy!(@team, body) end
      end
    end

    test "an association with a where: filter is refused" do
      schema = unique("Warden.Test.Compiled.Filtered")

      compile!("""
      defmodule #{schema} do
        use Ecto.Schema
        schema "teams" do
          field :workspace_id, :string
          has_many :open_memberships, Warden.Test.Ecto.TeamMembership, foreign_key: :team_id, where: [user_id: "x"]
        end
      end
      """)

      opts = "schema: #{schema}, as: :team, tenant: :workspace_id, actions: [:read]"

      assert_raise CompileError, ~r/`none: :open_memberships` has a `where:` filter/, fn ->
        policy!(opts, "allow :read, rule: public(), none: :open_memberships")
      end
    end

    test "if_nil: :tenant needs a tenanted policy" do
      opts = "schema: Warden.Test.Ecto.Issue, as: :issue, actions: [:read]"

      assert_raise CompileError, ~r/`if_nil: :tenant` needs a policy with a `:tenant`/, fn ->
        policy!(opts, "allow :read, through: :team, if_nil: :tenant")
      end

      assert_raise CompileError, ~r/`if_nil:` must be one of/, fn ->
        policy!(@issue, "allow :read, through: :team, if_nil: :allow")
      end
    end

    test "a bare rule is a rule: clause" do
      policy = policy!(@team, "allow :read, tenant_role(:member)")

      assert {:clauses, [], [%{parts: [rule: {:tenant_role, :member, _opts}]}]} =
               policy.__warden_ecto__(:info).actions.read
    end

    test "clause values are evaluated at compile time" do
      assert_raise CompileError, ~r/could not evaluate the argument of `allow`/, fn ->
        policy!(@team, "allow :read, rule: undefined_builder()")
      end
    end

    test "literal values are cast to their field types" do
      policy = policy!(@issue, "allow :read, rule: public(), where: [state: \"open\"]")
      assert {:clauses, [], [%{parts: parts}]} = policy.__warden_ecto__(:info).actions.read
      assert {:where, [state: :open]} in parts
    end
  end

  describe "scope callbacks" do
    test "an action takes a scope/4 or clauses, never both" do
      body = """
      allow :read, rule: public()
      def scope(:read, _actor, _tenant, _context), do: true
      """

      assert_raise CompileError, ~r/:read has both a scope\/4 clause and allow\/requires/, fn ->
        policy!(@team, body)
      end

      catch_all = """
      allow :read, rule: public()
      def scope(_action, _actor, _tenant, _context), do: true
      """

      assert_raise CompileError, ~r/:read has both/, fn -> policy!(@team, catch_all) end
    end

    test "every action has one or the other" do
      assert_raise CompileError, ~r/:read has neither allow clauses nor a scope\/4 clause/, fn ->
        policy!(@team, "")
      end

      opts = "schema: Warden.Test.Ecto.Team, as: :team, actions: [:read, :write]"
      body = "def scope(:read, _actor, _tenant, _context), do: true"

      assert_raise CompileError, ~r/:write has neither/, fn -> policy!(opts, body) end
    end

    test "a scope/4 clause for an unknown action fails" do
      body = "def scope(:reed, _actor, _tenant, _context), do: true"

      assert_raise CompileError, ~r/scope\/4 has a clause for :reed/, fn ->
        policy!(@team, body)
      end
    end

    test "scope/4 decides actions without clauses" do
      opts = "schema: Warden.Test.Ecto.Team, as: :team, actions: [:read, :write]"

      body = """
      allow :read, rule: public()
      def scope(:write, _actor, _tenant, _context), do: false
      """

      policy = policy!(opts, body)
      assert policy.__warden_ecto__(:info).actions.write == :scope
    end

    test "a bad scope/4 result raises Warden.PolicyError" do
      for bad <- [:ok, nil, "true", {:ok, true}, 1, Ecto.Query.from(note in Note)] do
        context = context(sam(), %{scope_result: bad})

        assert_raise Warden.PolicyError, ~r/must return an Ecto dynamic, true or false/, fn ->
          WardenEcto.scope(Note, context, :read, authorizer: Authz)
        end
      end
    end

    test "true and false are valid scope/4 results" do
      everything =
        WardenEcto.scope(Note, context(sam(), %{scope_result: true}), :read,
          authorizer: Authz,
          tenant: "t1"
        )

      nothing =
        WardenEcto.scope(Note, context(sam(), %{scope_result: false}), :read,
          authorizer: Authz,
          tenant: "t1"
        )

      assert inspect(everything) =~ ~s(where: n0.workspace_id in ^["t1"]>)
      assert inspect(nothing) =~ "where: false"
    end

    test "scope/4 runs once per actor, tenant and action per call" do
      user = %{id: "sam", memberships: %{"t1" => [:member], "t2" => [:member]}}
      _query = WardenEcto.scope(Note, context(user), :read, authorizer: Authz)

      assert_received {:scope, :read, "t1"}
      assert_received {:scope, :read, "t2"}
      refute_received {:scope, :read, _tenant}
      assert_received {:tenant_roles, "sam", "t1"}
      refute_received {:tenant_roles, "sam", "t1"}
    end
  end

  describe "the policy graph" do
    test "a through to a schema without a policy raises on first use and warns after compiling" do
      authorizer = unique("Warden.Test.Compiled.GraphAuthz")
      policy = unique("Warden.Test.Compiled.Orphan")

      code = """
      defmodule #{authorizer} do
        use Warden.Authorizer, roles: [:admin], policies: [#{policy}]
        def subject(context), do: context[:current_user]
        def roles(_user, _context), do: []
      end

      defmodule #{policy} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer},
          schema: Warden.Test.Ecto.Comment,
          as: :comment,
          tenant: :workspace_id,
          actions: [:read]

        allow :read, through: :issue
      end
      """

      warnings = ExUnit.CaptureIO.capture_io(:stderr, fn -> Code.compile_string(code) end)
      assert warnings =~ "Warden.Test.Ecto.Issue has no policy in"

      actor =
        Warden.actor(%{current_user: %{id: "abby"}}, authorizer: Module.concat([authorizer]))

      assert_raise Warden.PolicyError, ~r/Warden.Test.Ecto.Issue has no policy/, fn ->
        WardenEcto.scope(Comment, actor, :read, tenant: "t1")
      end
    end

    test "a through cycle over two policies raises on first use and warns after compiling" do
      {authorizer, first, _second} = cycle!()

      actor = Warden.actor(%{current_user: %{id: "abby"}}, authorizer: authorizer)

      assert_raise Warden.PolicyError, ~r/a through cycle/, fn ->
        WardenEcto.scope(first.__warden_ecto__(:info).schema, actor, :read, tenant: "t1")
      end
    end

    test "a tenanted child cannot go through an untenanted parent" do
      authorizer = unique("Warden.Test.Compiled.TenancyAuthz")
      child = unique("Warden.Test.Compiled.TenancyChild")
      parent = unique("Warden.Test.Compiled.TenancyParent")

      code = """
      defmodule #{authorizer} do
        use Warden.Authorizer, roles: [:admin], policies: [#{child}, #{parent}]
        def subject(context), do: context[:current_user]
        def roles(_user, _context), do: []
      end

      defmodule #{parent} do
        use Warden.Ecto.Policy, authorizer: #{authorizer}, schema: Warden.Test.Ecto.Team, as: :team, actions: [:read]
        allow :read, rule: public()
      end

      defmodule #{child} do
        use Warden.Ecto.Policy,
          authorizer: #{authorizer}, schema: Warden.Test.Ecto.Issue, as: :issue,
          tenant: :workspace_id, actions: [:read]

        allow :read, through: :team
      end
      """

      warnings = ExUnit.CaptureIO.capture_io(:stderr, fn -> Code.compile_string(code) end)
      assert warnings =~ "must both have a `:tenant` or both have none"
    end

    test "the policies of the suite are valid" do
      for policy <- Authz.__warden_catalog__().policies do
        assert Graph.validate(policy) == []
      end
    end
  end

  # Two schemas that belong to each other, each with a policy that goes through the
  # other.
  defp cycle! do
    authorizer = unique("Warden.Test.Compiled.CycleAuthz")
    first = unique("Warden.Test.Compiled.CycleFirst")
    second = unique("Warden.Test.Compiled.CycleSecond")
    first_schema = unique("Warden.Test.Compiled.CycleFirstSchema")
    second_schema = unique("Warden.Test.Compiled.CycleSecondSchema")

    code = """
    defmodule #{first_schema} do
      use Ecto.Schema
      schema "firsts" do
        field :workspace_id, :string
        belongs_to :second, #{second_schema}
      end
    end

    defmodule #{second_schema} do
      use Ecto.Schema
      schema "seconds" do
        field :workspace_id, :string
        belongs_to :first, #{first_schema}
      end
    end

    defmodule #{authorizer} do
      use Warden.Authorizer, roles: [:admin], policies: [#{first}, #{second}]
      def subject(context), do: context[:current_user]
      def roles(_user, _context), do: []
    end

    defmodule #{first} do
      use Warden.Ecto.Policy,
        authorizer: #{authorizer}, schema: #{first_schema}, as: :first,
        tenant: :workspace_id, actions: [:read]

      allow :read, through: :second
    end

    defmodule #{second} do
      use Warden.Ecto.Policy,
        authorizer: #{authorizer}, schema: #{second_schema}, as: :second,
        tenant: :workspace_id, actions: [:read]

      allow :read, through: :first
    end
    """

    warnings = ExUnit.CaptureIO.capture_io(:stderr, fn -> Code.compile_string(code) end)
    assert warnings =~ "a through cycle"
    {Module.concat([authorizer]), Module.concat([first]), Module.concat([second])}
  end

  describe "functions without a database" do
    test "scope/4 needs a policy for the root schema" do
      assert_raise Warden.PolicyError,
                   ~r/lists no policy for Warden.Test.Ecto.TeamMembership/,
                   fn ->
                     WardenEcto.scope(Warden.Test.Ecto.TeamMembership, actor(sam()), :read)
                   end

      assert_raise Warden.PolicyError, ~r/has no action :delete/, fn ->
        WardenEcto.scope(Issue, actor(sam()), :delete)
      end

      assert_raise ArgumentError, ~r/root binding is named :other/, fn ->
        query = from(issue in Issue, as: :other)
        WardenEcto.scope(query, actor(sam()), :read)
      end
    end

    test "scope/4 names the root binding" do
      query = WardenEcto.scope(from(issue in Issue), actor(sam()), :read)
      assert query.from.as == :issue
      assert query.aliases.issue == 0
    end

    test "dataloader_query/2 scopes schemas with a policy and passes others through" do
      params = %{warden_actor: actor(sam())}

      assert %Ecto.Query{from: %{as: :issue}, wheres: [_scope]} =
               WardenEcto.dataloader_query(Issue, params)

      assert WardenEcto.dataloader_query(Warden.Test.Ecto.TeamMembership, params) ==
               Warden.Test.Ecto.TeamMembership

      assert_raise Warden.PolicyError, ~r/needs a :warden_actor param/, fn ->
        WardenEcto.dataloader_query(Issue, %{})
      end
    end

    test "update_all/4 and delete_all/3 refuse a query that is not write-scoped" do
      unscoped = from(issue in Issue)
      read_scoped = WardenEcto.scope(Issue, actor(sam()), :read)
      widened = Issue |> WardenEcto.scope(actor(sam()), :write) |> or_where(true)

      for query <- [unscoped, read_scoped, widened] do
        assert_raise Warden.PolicyError, ~r/refuses a query/, fn ->
          WardenEcto.update_all(Warden.Test.Repo, query, [set: [title: "x"]], [])
        end

        assert_raise Warden.PolicyError, ~r/refuses a query/, fn ->
          WardenEcto.delete_all(Warden.Test.Repo, query, [])
        end
      end
    end

    test "a system actor of another kind gets false without asking the policy" do
      job = Warden.system_actor(Authz, kind: :job, tenant: "t1")
      query = WardenEcto.scope(Note, job, :read, context: %{test_pid: self()})

      refute_received {:scope, _action, _tenant}
      assert inspect(query) =~ "false"
      _unused = Team
    end
  end
end
