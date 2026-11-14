# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Policy do
    @moduledoc """
    A policy over an Ecto schema: one declaration per action that Warden turns into a
    query scope, a single check, a filter over loaded rows and the GraphQL object rule.

        defmodule MyApp.Authz.Issues do
          use Warden.Ecto.Policy,
            authorizer: MyApp.Authz,
            schema: MyApp.Issues.Issue,
            as: :issue,
            tenant: :workspace_id,
            repo: MyApp.Repo,
            actions: [:read, :write],
            write_actions: [:write]

          allow :read, through: :team, where: [trashed_at: nil]
          allow :write, through: {:team, :read}, rule: tenant_role(:member)
          requires :write, credential_scope("issues:write")
        end

    The authorizer lists the policy in its `policies:`, and every front end uses it:
    `Warden.Ecto.scope/4` for queries, `Warden.Ecto.allowed?/4` and `Warden.Ecto.filter/4`
    for loaded rows, and `can(MyApp.Authz.Issues, :read)` as a rule in GraphQL, Plug and
    the core API.

    ## Options

      * `:authorizer` (required) - the authorizer whose `policies:` lists this module.
      * `:schema` (required) - the Ecto schema. It needs exactly one primary key field.
      * `:as` (required) - the name of the root binding. Scope callbacks and `when:`
        clauses build dynamics over it: `dynamic([issue: issue], ...)`.
      * `:actions` (required) - the actions the policy decides.
      * `:tenant` - the field that holds the row's tenant. Without it the schema has no
        tenants.
      * `:null_tenant` - `true` to decide rows whose tenant field is `NULL` (with tenant
        `nil`). Default `false`: such rows are never visible.
      * `:repo` - the repo for the queries Warden runs itself (single checks, lists,
        `allowed_actors/3`, `explain/3`, `to_sql/4`).
      * `:system_kinds` - the system actor kinds the policy decides for. Every other
        system actor gets `false`. Default `[]`.
      * `:subject_id` - the key of the actor's subject that holds its id, for `actor_in:`,
        `member_of:` and `grant:`. Default `:id`.
      * `:write_actions` - the actions that `Warden.Ecto.update_all/4` and
        `Warden.Ecto.delete_all/3` accept a scope for. Default `[]`.

    ## Per action: a scope callback or clauses

    Each action gets either a hand-written `c:scope/4` or declarative `allow` and
    `requires` clauses, never both (compile error). `allow` clauses are ORed, `requires`
    clauses are ANDed with them, and the keys inside one clause are ANDed:

        allow :read, rule: tenant_role(:member), where: [private: false]
        allow :read, member_of: {MyApp.Teams.Membership, :team_id, :user_id}
        requires :read, session()                 # a bare rule means `rule: rule`

    Clause keys:

    | Key | Means |
    |---|---|
    | `rule: r` | the actor passes the Warden rule `r` in the row's tenant (no row) |
    | `where: [field: value]` | the field equals a literal (`nil` means `IS NULL`) |
    | `through: assoc` / `{assoc, action}` | the `belongs_to` parent is allowed under its own policy (default: the same action), in the same tenant |
    | `if_nil: :deny \\| :tenant` | with `through:`, a `nil` foreign key denies (default) or admits members of the tenant |
    | `through_any: assoc` / `{assoc, action}` | at least one row of a `has_many` or `many_to_many` association is allowed under its policy |
    | `none: assoc` | the association has no rows |
    | `actor_in: [fields]` | one of the fields equals the actor's subject id |
    | `member_of: {schema, row_key, actor_key}` | a row in `schema` links this row to the actor |
    | `grant: {schema, row_key, grantee_key, expires_at: field}` | a share row for the actor that has not expired (`expires_at` `NULL` never expires) |
    | `through_type: {type_field, id_field, %{type => policy}}` | a polymorphic parent allowed under the policy for its type; a type not in the map denies |
    | `within: {bounds_key, field}` | the field is in the actor's `bounds[bounds_key]` (a missing key denies) |
    | `when: fun` | `fun.(actor, tenant, context)` returns a dynamic, `true` or `false`, like `c:scope/4` |

    Every `allow` clause needs a key about the actor (all but `where:`, `none:` and
    `if_nil:`). For rows every actor may see, anonymous ones included, say so with
    `rule: public()`.

    A system actor passes only `allow` clauses whose `rule:` names its kind
    (`rule: kind(:webhook)`), and only when its kind is in `:system_kinds`. `requires`
    clauses apply to every actor.

    A `rule:` clause is about the actor in the tenant being decided: `tenant_role/1` reads
    that tenant, and checks get `value: nil` and the tenant in `args.tenant`. `can/2,3`
    and `covered()` are not allowed there.

    ## Compile-time and first-use errors

    These fail compilation: unknown options, actions, clause keys, fields and
    associations; a `through` that is not a `belongs_to`; a `through` or `through_any`
    back to the policy's own schema (a cycle); an action with both clauses and a `scope/4`
    clause, or with neither; an action with `requires` but no `allow`.

    What needs the other policies (a `through` to a schema without a `Warden.Ecto.Policy`,
    a cycle over several policies, a parent of another authorizer or without the action,
    a tenanted child with an untenanted parent or the other way round) is checked when the
    whole project has compiled: it prints a compiler warning (so `--warnings-as-errors`
    fails), and the policy raises `Warden.PolicyError` on first use.

    ## Callbacks

    All are optional. A hand-written `c:scope/4` decides the actions that have no clauses.
    A hand-written `c:allowed?/4` (and `c:allowed_many/4`) decides loaded structs without a
    query; it must agree with the scope. Without it, Warden decides a loaded struct from
    the clauses in memory where that is exact (literal fields, loaded parents) and with one
    query otherwise. `{schema, id}` values (from `can(policy, action, arg: path)`) are
    always decided with a query.
    """

    alias Warden.Actor
    alias Warden.Ecto.Decide
    alias Warden.Ecto.Policy.Compiler

    @doc """
    Returns the scope of `action` for `actor` in `tenant` (`nil` for an untenanted schema
    or a `NULL` tenant): an `Ecto.Query.dynamic_expr()` over the `:as` binding, `true`
    (every row of the tenant) or `false` (none). Anything else raises `Warden.PolicyError`.

    Called at most once per actor, tenant and action per Warden call. `actor` is never a
    delegated actor: Warden calls the scope for each side of a delegation and ANDs them.
    """
    @callback scope(action :: atom, Actor.t(), tenant :: term, context :: map) ::
                Ecto.Query.dynamic_expr() | boolean

    @doc "Decides `action` for a loaded struct without a query."
    @callback allowed?(action :: atom, Actor.t(), struct, context :: map) ::
                Warden.Policy.result()

    @doc "Decides `action` for loaded structs without a query: one result per struct, in order."
    @callback allowed_many(action :: atom, Actor.t(), [struct], context :: map) ::
                [Warden.Policy.result()]

    @optional_callbacks scope: 4, allowed?: 4, allowed_many: 4

    @rule_builders [
      public: 0,
      authenticated: 0,
      deny: 0,
      role: 1,
      any_role: 1,
      permission: 1,
      all_permissions: 1,
      any_permission: 1,
      check: 1,
      check: 2,
      all_of: 1,
      any_of: 1,
      tenant_role: 1,
      tenant_role: 2,
      kind: 1,
      credential_scope: 1,
      session: 0,
      can: 2,
      can: 3,
      covered: 0
    ]

    defmacro __using__(opts) do
      env = __CALLER__
      {opts, _binding} = Code.eval_quoted(opts, [], env)

      {core, options} =
        case Compiler.validate_options(opts, env.module) do
          {:ok, core, options} -> {core, options}
          {:error, errors} -> compile_error!(env, "invalid Warden.Ecto.Policy options", errors)
        end

      # Registered now, not in the module body: the clause macros record into it while
      # the body expands.
      Module.register_attribute(env.module, :warden_ecto_clauses, accumulate: true)

      quote do
        @behaviour Warden.Ecto.Policy
        @before_compile Warden.Ecto.Policy
        @after_verify {Warden.Ecto.Policy.Graph, :after_verify}

        import Warden.Ecto.Policy, only: [allow: 2, requires: 2]

        @warden_ecto_core unquote(Macro.escape(core))
        @warden_ecto_options unquote(Macro.escape(options))

        # The entry points Warden calls (see Warden.Policy.Dispatch). They must be public,
        # and are hidden from the user's docs.
        # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def __warden_policy__(:info), do: @warden_ecto_core

        # credo:disable-for-lines:4 ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def __warden_decide__(action, actor, values, context),
          do: unquote(Decide).decide(__MODULE__, action, actor, values, context)
      end
    end

    @doc """
    Adds an `allow` clause for `action`: a keyword list of clause keys (ANDed), or a bare
    rule (`allow :read, tenant_role(:member)` means `rule: tenant_role(:member)`).
    `allow` clauses of one action are ORed.
    """
    defmacro allow(action, clause), do: record(:allow, action, clause, __CALLER__)

    @doc """
    Adds a `requires` clause for `action`: like `allow/2`, but every `requires` clause of
    the action must pass, on top of one `allow` clause.
    """
    defmacro requires(action, clause), do: record(:require, action, clause, __CALLER__)

    @doc false
    defmacro __before_compile__(env) do
      core = Module.get_attribute(env.module, :warden_ecto_core)
      options = Module.get_attribute(env.module, :warden_ecto_options)
      clauses = env.module |> Module.get_attribute(:warden_ecto_clauses) |> Enum.reverse()
      patterns = Compiler.scope_patterns(env.module)

      actions =
        case Compiler.plan(clauses, core, options, patterns) do
          {:ok, actions} -> actions
          {:error, errors} -> compile_error!(env, "invalid Warden.Ecto.Policy", errors)
        end

      info =
        Map.merge(options, %{
          policy: env.module,
          authorizer: core.authorizer,
          system_kinds: core.system_kinds,
          actions: actions,
          allowed?: Module.defines?(env.module, {:allowed?, 4}),
          allowed_many?: Module.defines?(env.module, {:allowed_many, 4})
        })

      quote do
        # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def __warden_ecto__(:info), do: unquote(Macro.escape(info))
      end
    end

    defp record(kind, action_ast, clause_ast, env) do
      action = eval!(action_ast, env, kind)
      index = env.module |> Module.get_attribute(:warden_ecto_clauses) |> length()
      {parts, functions} = parts(clause_ast, index, env, kind)
      clause = %{kind: kind, action: action, index: index, line: env.line, parts: parts}
      Module.put_attribute(env.module, :warden_ecto_clauses, clause)
      {:__block__, [], functions}
    end

    defp parts(clause_ast, index, env, kind) do
      if Keyword.keyword?(clause_ast) and clause_ast != [] do
        Enum.map_reduce(clause_ast, [], fn
          {:when, fun_ast}, functions ->
            name = :"__warden_when_#{index}__"
            {{:when, {:function, name}}, [when_function(name, fun_ast) | functions]}

          {key, value_ast}, functions ->
            {{key, eval!(value_ast, env, kind)}, functions}
        end)
      else
        {[rule: eval!(clause_ast, env, kind)], []}
      end
    end

    # A `when:` function becomes a public function of the policy, so the clause plan can
    # refer to it by name.
    defp when_function(name, fun_ast) do
      quote do
        # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
        @doc false
        def unquote(name)(actor, tenant, context), do: unquote(fun_ast).(actor, tenant, context)
      end
    end

    # Clause values are built at compile time, with the rule builders in scope.
    defp eval!(ast, env, kind) do
      wrapped =
        quote do
          import Warden.Rule, only: unquote(@rule_builders), warn: false
          unquote(ast)
        end

      {value, _binding} = Code.eval_quoted(wrapped, [], env)
      value
    rescue
      error ->
        message = """
        could not evaluate the argument of `#{macro_name(kind)}` at compile time: \
        #{Exception.message(error)}\
        """

        reraise CompileError, [file: env.file, line: env.line, description: message], []
    end

    defp macro_name(:allow), do: "allow"
    defp macro_name(:require), do: "requires"

    @spec compile_error!(Macro.Env.t(), String.t(), [String.t()]) :: no_return()
    defp compile_error!(env, title, errors) do
      description =
        "#{title} in #{inspect(env.module)}:\n" <> Enum.map_join(errors, "\n", &("  * " <> &1))

      raise CompileError, file: env.file, line: env.line, description: description
    end
  end
end
