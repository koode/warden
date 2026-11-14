defmodule Warden.CatalogTest do
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.CompileHelpers

  alias Warden.Authorizer.Catalog
  alias Warden.Rule
  alias Warden.Test.Authz

  defp build(opts), do: Catalog.build([roles: [:admin]] ++ opts)

  defp errors(opts) do
    {:error, errors} = build(opts)
    Enum.join(errors, "\n")
  end

  defp compile_authorizer(opts, body) do
    compile!("""
    defmodule #{unique("Warden.Test.Compiled.CatalogAuthz")} do
      use Warden.Authorizer, #{opts}
      def subject(context), do: context[:user]
      def roles(user, _context), do: user.roles
      #{body}
    end
    """)
  end

  describe "checks" do
    test "0.1 atom lists keep working" do
      assert {:ok, catalog} = build(checks: [:self, :owner])
      assert catalog.checks == [:self, :owner]
      assert catalog.check_specs.self == Catalog.default_check_spec()
    end

    test "name: options entries are parsed" do
      assert {:ok, catalog} =
               build(
                 kinds: [:webhook],
                 checks: [
                   :self,
                   email_visible: [batch: true],
                   code_readable: [batch: true, timeout: 3_000],
                   member: [
                     opts: [role: {:in, [:owner, :admin]}, scope: :string],
                     required: [:role]
                   ],
                   team: [system_kinds: [:webhook]]
                 ]
               )

      assert catalog.checks == [:self, :email_visible, :code_readable, :member, :team]
      assert catalog.check_specs.email_visible.batch
      assert catalog.check_specs.code_readable.timeout == 3_000
      assert catalog.check_specs.member.required == [:role]
      assert catalog.check_specs.team.system_kinds == [:webhook]
    end

    test "invalid entries are reported together" do
      message =
        errors(
          checks: [
            "string",
            bad_batch: [batch: :yes],
            bad_timeout: [timeout: 0],
            bad_type: [opts: [role: :float]],
            bad_required: [required: [:role]],
            missing_required: [opts: [scope: :string], required: [:role]],
            bad_kind: [system_kinds: [:user]],
            unknown_option: [cache: true]
          ]
        )

      assert message =~ "check :bad_batch: `batch:` must be a boolean"
      assert message =~ "check :bad_timeout: `timeout:` must be a positive integer"
      assert message =~ "check :bad_type: option :role has an unknown type :float"
      assert message =~ "check :bad_required: `required:` needs an `opts:` schema"
      assert message =~ "check :missing_required: required option :role is not in `opts:`"
      assert message =~ "check :bad_kind: `system_kinds:` names :user"
      assert message =~ "check :unknown_option: unknown options [:cache]"
      assert message =~ ~s|`:checks` entry "string"|
    end

    test "a name declared twice with different options fails" do
      assert errors(checks: [:self, self: [batch: true]]) =~ "`:checks` declares :self twice"
      assert {:ok, _catalog} = build(checks: [:self, :self])
    end

    test "batched checks require check_many/2, others check/2" do
      assert_raise CompileError,
                   ~r/declares batched checks \[:many\] but does not define check_many\/2/,
                   fn ->
                     compile_authorizer("roles: [:a], checks: [many: [batch: true]]", "")
                   end

      assert_raise CompileError, ~r/declares checks \[:one\] but does not define check\/2/, fn ->
        compile_authorizer(
          "roles: [:a], checks: [:one, many: [batch: true]]",
          "def check_many(_name, checks), do: Enum.map(checks, fn _check -> true end)"
        )
      end

      assert compile_authorizer(
               "roles: [:a], checks: [many: [batch: true]]",
               "def check_many(_name, checks), do: Enum.map(checks, fn _check -> true end)"
             )
    end
  end

  describe "check option schemas in rules" do
    setup do
      {:ok, catalog} =
        build(
          checks: [
            :free,
            member: [
              opts: [role: {:in, [:owner, :admin]}, scope: :string, ids: {:list, :integer}],
              required: [:role]
            ]
          ]
        )

      %{catalog: catalog}
    end

    test "valid options pass, a check without a schema accepts anything", %{catalog: catalog} do
      assert Rule.validate(check(:member, role: :owner), catalog) == :ok
      assert Rule.validate(check(:member, role: :admin, scope: "x", ids: [1, 2]), catalog) == :ok
      assert Rule.validate(check(:free, anything: make_ref()), catalog) == :ok
    end

    test "unknown, missing and mistyped options fail", %{catalog: catalog} do
      assert {:error, [unknown]} = Rule.validate(check(:member, role: :owner, extra: 1), catalog)
      assert unknown =~ "check(:member) has an unknown option :extra"

      assert {:error, [missing]} = Rule.validate(check(:member, scope: "x"), catalog)
      assert missing =~ "check(:member) needs the option :role"

      assert {:error, [not_in]} = Rule.validate(check(:member, role: :guest), catalog)
      assert not_in =~ "option :role must be {:in, [:owner, :admin]}"

      assert {:error, [bad_list]} =
               Rule.validate(check(:member, role: :owner, ids: ["1"]), catalog)

      assert bad_list =~ "option :ids must be {:list, :integer}"
    end

    test "Absinthe schemas fail compilation on a bad check option" do
      assert_raise CompileError, ~r/check\(:typed\) needs the option :role/, fn ->
        compile_schema(
          """
            query do
              field :a, :string do
                authorize check(:typed, [])
              end
            end
          """,
          "authorizer: Warden.Test.V2.Authz"
        )
      end
    end
  end

  describe "kinds, tenant roles, credential scopes and policies" do
    test "kinds always include :user and reject :anonymous" do
      assert {:ok, catalog} = build(kinds: [:agent])
      assert catalog.kinds == MapSet.new([:user, :agent])
      assert {:ok, %{kinds: kinds}} = build([])
      assert kinds == MapSet.new([:user])
      assert errors(kinds: [:anonymous]) =~ "`:kinds` must not contain :anonymous"
      assert errors(kinds: ["agent"]) =~ "`:kinds` must be a list of atoms"
      assert errors(kinds: [:agent, :agent]) =~ "`:kinds` contains duplicates"
    end

    test "tenant roles and their hierarchy" do
      assert {:ok, catalog} =
               build(
                 tenant_roles: [:owner, :member, :guest],
                 tenant_role_hierarchy: %{owner: [:member], member: [:guest]}
               )

      assert catalog.implied_tenant_roles.owner == MapSet.new([:owner, :member, :guest])
      assert catalog.implied_tenant_roles.guest == MapSet.new([:guest])

      assert errors(tenant_roles: [:a, :b], tenant_role_hierarchy: %{a: [:b], b: [:a]}) =~
               "`:tenant_role_hierarchy` has a cycle: :a -> :b -> :a"

      assert errors(tenant_roles: [:a], tenant_role_hierarchy: %{a: [:z]}) =~
               "`:tenant_role_hierarchy` :a implies :z, which is not a tenant role"

      assert errors(tenant_role_hierarchy: %{a: [:b]}) =~
               "`:tenant_role_hierarchy` needs `:tenant_roles`"

      assert errors(tenant_roles: []) =~ "`:tenant_roles` must be a non-empty list of atoms"
      assert {:ok, %{tenant_roles: nil}} = build([])
    end

    test "tenant roles require tenant_roles/3" do
      assert_raise CompileError,
                   ~r/declares `tenant_roles:` but does not define tenant_roles\/3/,
                   fn ->
                     compile_authorizer("roles: [:a], tenant_roles: [:member]", "")
                   end

      assert compile_authorizer(
               "roles: [:a], tenant_roles: [:member]",
               "def tenant_roles(_subject, _tenant, _context), do: []"
             )
    end

    test "credential scopes and policies" do
      assert {:ok, catalog} = build(credential_scopes: ["issues:read"], policies: [Some.Policy])
      assert catalog.credential_scopes == MapSet.new(["issues:read"])
      assert catalog.policies == [Some.Policy]
      assert {:ok, %{credential_scopes: nil, policies: []}} = build([])

      assert errors(credential_scopes: [:read]) =~
               "`:credential_scopes` must be a list of strings"

      assert errors(policies: ["Policy"]) =~ "`:policies` must be a list of modules"
      assert errors(policies: [Some.Policy, Some.Policy]) =~ "`:policies` contains duplicates"
    end

    test "the catalog names its authorizer" do
      assert Authz.__warden_catalog__().authorizer == Authz
    end
  end
end
