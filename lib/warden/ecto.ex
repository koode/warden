# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto do
    @moduledoc """
    Query scopes and row checks from `Warden.Ecto.Policy` modules (needs `ecto`).

    One policy per schema answers every question about its rows: which rows a query may
    return (`scope/4`), whether one row is allowed (`allowed?/4`, `authorize/4`), which of
    many loaded rows are (`filter/4`), which actors may see a row (`allowed_actors/4`), and
    why (`explain/4`). GraphQL, Plug and the core API ask the same policy through
    `can(policy, action)`.

        import Ecto.Query

        query = from(issue in MyApp.Issues.Issue, where: issue.state == :open)

        query |> Warden.Ecto.scope(actor, :read) |> Repo.all()                 # every tenant of the actor
        query |> Warden.Ecto.scope(actor, :read, tenant: workspace_id) |> Repo.all()

        Warden.Ecto.allowed?(actor, :write, issue)                           # a loaded struct
        Warden.Ecto.allowed?(actor, :write, {MyApp.Issues.Issue, id})        # by id: one EXISTS query
        Warden.Ecto.filter(actor, :read, issues)                             # one query, order kept

        issues = Warden.Ecto.all(Repo, query, actor, :read)                  # scoped rows, trusted later

    Every function takes an actor or a context map, and `authorizer:` like the core API
    (`Warden`): the explicit option, else the actor's authorizer, else the configured
    default. The policy is the one the authorizer lists for the row's schema.

    ## Tenants

    With `tenant:`, `scope/4` returns the rows of that tenant the actor may see
    (`tenant: nil` means rows whose tenant field is `NULL`, for a policy with
    `null_tenant: true`). Without it, the scope covers every tenant from
    `c:Warden.Authorizer.tenants/2`: `(tenant = t1 AND scope_t1) OR (tenant = t2 AND
    scope_t2) ...`. A credential bound to a tenant narrows that to its tenant, and an
    unbound system actor has no tenants. Single checks of a loaded struct use the
    struct's tenant; checks by id use the scope over every tenant.

    ## Preloads and unions

    `scope/4` refuses a query with preloads, which would load children without their
    policy, and one with `union`, `union_all`, `intersect` or `except`, whose other arms
    would stay unscoped. Scope the children and each arm instead:

        comments = Warden.Ecto.scope(MyApp.Comment, actor, :read)
        issues = MyApp.Issues.Issue |> Warden.Ecto.scope(actor, :read) |> preload(comments: ^comments)

        union_all(Warden.Ecto.scope(open, actor, :read), ^Warden.Ecto.scope(recent, actor, :read))

    In GraphQL, `dataloader_query/2` scopes every Dataloader load.

    ## Delegation

    For an actor acting on behalf of another (`Warden.on_behalf_of/3`), every scope and
    check is the AND of both actors' (over the tenants both are in), so it is never wider
    than either.

    ## Telemetry

    `scope/4` (and `all/5`, `to_sql/4`, `dataloader_query/2`), `allowed?/4`, `authorize/4`,
    `filter/4` and `allowed_actors/4` emit `[:warden, :decision]` with `layer: :ecto`
    (`kind: :scope` for scopes, `:call` for checks). `explain/4`, `update_all/4`,
    `delete_all/3` and `preload_ids/4` emit none.
    """

    import Ecto.Query, only: [dynamic: 1, where: 2]

    alias Warden.{Actor, Decision, Rule, Telemetry}
    alias Warden.Ecto.{Audience, Explain, Guard, Info, Mark, Scope}
    alias Warden.Ecto.Policy.Graph

    @default_action :read

    @typedoc """
    Options: `:authorizer`, `:context` (the context for policy callbacks when the first
    argument is an actor) and, for `scope/4`, `to_sql/4` and `preload_ids/4`, `:tenant`
    and `:prefix` (the query prefix the scope will run in, for the parent ids that
    `through: {assoc, action, resolve: :ids}` reads while the scope is built).
    """
    @type opts :: keyword

    @typedoc "A loaded struct of a schema with a policy, or `{schema, id}`."
    @type row :: struct | {module, term}

    @doc """
    Narrows `queryable` (a schema or a query whose root is one) to the rows that the actor
    may `action`. The root binding gets the policy's `as:` name when it has none.

        Warden.Ecto.scope(MyApp.Issues.Issue, actor, :read, tenant: workspace_id)
        Warden.Ecto.scope(query, context, :read)          # every tenant of the actor

    Raises `Warden.PolicyError` when the authorizer lists no `Warden.Ecto.Policy` for the
    root schema, the action is unknown, a scope callback returns anything but a dynamic,
    `true` or `false`, or a CTE of the query is named like a table the scope reads
    (Postgres would read the CTE instead).

    Raises `ArgumentError` for queries it cannot scope as a whole:

      * `union`, `union_all`, `intersect` and `except`: scope each arm, then combine
        them (`union_all(scope(arm_a, ...), ^scope(arm_b, ...))`);
      * preloads, which would load children without their policy: preload a scoped query
        instead, `preload(comments: ^Warden.Ecto.scope(Comment, actor, :read))`, or load
        them with `dataloader_query/2`.
    """
    @spec scope(Ecto.Queryable.t(), Warden.actor_or_context(), atom, opts) :: Ecto.Query.t()
    def scope(queryable, actor_or_context, action, opts \\ []) when is_list(opts) do
      {actor, context, authorizer} = Decision.setup(actor_or_context, opts)
      query = Ecto.Queryable.to_query(queryable)
      info = query |> root_schema!() |> then(&Info.policy_for!(authorizer, &1))
      Guard.compose!(query)
      Graph.ensure_valid!(info.policy)

      which = if Keyword.has_key?(opts, :tenant), do: {:tenant, opts[:tenant]}, else: :all
      state = Scope.new(context, Keyword.get(opts, :prefix))
      {verdict, actor, _state} = Scope.scope(info, action, actor, which, state)

      emit_scope(info, action, actor, Keyword.get(opts, :tenant), verdict)

      scoped =
        query
        |> named_root!(info)
        |> where(^as_dynamic(verdict))
        |> Guard.mark(info.policy, action)

      Guard.ctes!(scoped)
      scoped
    end

    @doc """
    Reads the ids that `through: {assoc, action, resolve: :ids}` compares a foreign key
    with, and returns the actor with them cached, like
    `Warden.Actor.preload_tenant_roles/3`. Pass the returned actor to later calls of the
    request: their scopes read the ids from the actor instead of running the parent's
    scope again.

        actor = Warden.Ecto.preload_ids(actor, MyApp.Teams.Team, :read)
        issues = MyApp.Issues.Issue |> Warden.Ecto.scope(actor, :read) |> Repo.all()

    `policy_or_schema` is the parent (the policy, or the schema the authorizer lists it
    for) and `action` the parent's action that the `through:` names. Takes `tenant:`
    (else every tenant of the actor, as `scope/4`), `prefix:`, `authorizer:` and
    `context:`. The parent's scope runs once per tenant, on its primary key; for a
    delegated actor once for each side, each cached in that side's own struct.

    A cached entry is used only for the same parent policy, action, tenant, query prefix
    and actor side; anything else reads the ids as before. The ids are as fresh as the
    actor: keep the actor for one request, as with tenant roles. They were read with the
    context of this call.
    """
    @spec preload_ids(Actor.t(), module, atom, opts) :: Actor.t()
    def preload_ids(%Actor{} = actor, policy_or_schema, action, opts \\ [])
        when is_atom(policy_or_schema) and is_list(opts) do
      {actor, context, authorizer} = Decision.setup(actor, opts)
      info = ids_policy!(authorizer, policy_or_schema)
      Graph.ensure_valid!(info.policy)

      which = if Keyword.has_key?(opts, :tenant), do: {:tenant, opts[:tenant]}, else: :all
      state = Scope.new(context, Keyword.get(opts, :prefix))
      Scope.preload_ids(info, action, actor, which, state)
    end

    # The policy the authorizer lists for a schema, or for the schema of a policy; a
    # policy the authorizer does not list for its schema would never be asked.
    defp ids_policy!(authorizer, policy_or_schema) do
      if Info.ecto_policy?(policy_or_schema) do
        schema = Info.fetch!(policy_or_schema).schema
        info = Info.policy_for!(authorizer, schema)

        if info.policy != policy_or_schema do
          raise Warden.PolicyError, """
          #{inspect(authorizer)} lists #{inspect(info.policy)} for #{inspect(schema)}, not \
          #{inspect(policy_or_schema)}\
          """
        end

        info
      else
        Info.policy_for!(authorizer, policy_or_schema)
      end
    end

    @doc """
    Runs `repo.all/2` over `scope/4` of `queryable` and returns the rows, each marked as
    admitted by that scope for this actor and action:

        issues = Warden.Ecto.all(Repo, MyApp.Issues.Issue, actor, :read, tenant: workspace_id)
        Warden.Ecto.filter(actor, :read, issues)    # no query: every row is admitted

    A later decision about a marked struct (`can(policy, action)` as a GraphQL object
    rule, `allowed?/4`, `filter/4`, `Warden.filter/4`) allows it without running the
    policy or a query, once the gates before the policy pass: the system kinds, the
    actor's tenants (`c:Warden.Authorizer.tenants/2`) and a bound credential's tenant
    (still `:tenant_binding` for another tenant). A mark is trusted only

      * for the same actor instance: an actor built again (from the same context, in a
        later request, by `Warden.on_behalf_of/3`) decides the row through its policy;
      * for the same policy and action: rows loaded for `:read` are decided as usual for
        `:write`;
      * for the struct as loaded: a struct whose persisted fields or prefix changed is
        decided as it is.

    Pass an actor, not a context map, and use that actor for the decisions: a context map
    builds a new actor on every call. In GraphQL that is the actor of the document
    execution, which the object rules use.

    Only structs of the policy's schema that the query returns as its root binding are
    marked, never preloaded children (`scope/4` refuses preloads anyway), structs selected
    from a join, a `select_merge`, or a struct whose `__meta__.context` is already set
    (Postgres and MySQL leave it `nil`; other adapters may use it). Other rows come back
    as they are.

    Options: those of `scope/4` (`:authorizer`, `:context`, `:tenant`, `:prefix`); every
    other option, and `:prefix`, goes to `repo.all/2`. Emits the telemetry of `scope/4`.
    """
    @spec all(module, Ecto.Queryable.t(), Warden.actor_or_context(), atom, opts) :: list
    def all(repo, queryable, actor_or_context, action, opts \\ []) when is_list(opts) do
      {scope_opts, repo_opts} = Keyword.split(opts, [:authorizer, :context, :tenant, :prefix])
      {actor, context, authorizer} = Decision.setup(actor_or_context, scope_opts)
      scope_opts = Keyword.merge(scope_opts, authorizer: authorizer, context: context)
      scoped = scope(queryable, actor, action, scope_opts)
      info = Info.policy_for!(authorizer, root_schema!(scoped))
      repo_opts = Keyword.merge(repo_opts, Keyword.take(scope_opts, [:prefix]))
      rows = repo.all(scoped, repo_opts)
      Mark.mark_all(rows, info, action, actor, scoped)
    end

    @doc """
    Returns `true` when the actor may `action` the row: a loaded struct, or `{schema, id}`.

    For a struct, the policy's hand-written `allowed?/4` answers when it has one;
    otherwise Warden decides from the clauses in memory where that is exact, and with one
    query otherwise. `{schema, id}` is always one query inside the scope.
    """
    @spec allowed?(Warden.actor_or_context(), atom, row, opts) :: boolean
    def allowed?(actor_or_context, action, row, opts \\ []) when is_list(opts),
      do: authorize(actor_or_context, action, row, opts) == :ok

    @doc """
    Like `allowed?/4`, but returns `:ok` or `{:error, %Warden.Denial{kind: :call}}`, as
    `Warden.authorize/3` does for the rule `can(policy, action)`.
    """
    @spec authorize(Warden.actor_or_context(), atom, row, opts) ::
            :ok | {:error, Warden.Denial.t()}
    def authorize(actor_or_context, action, row, opts \\ []) when is_list(opts) do
      {actor, context, authorizer} = Decision.setup(actor_or_context, opts)
      info = Info.policy_for!(authorizer, row_schema!(row))
      rule = Rule.can(info.policy, action)
      call_opts = [authorizer: authorizer, context: context, value: row]
      Decision.authorize(actor, rule, call_opts, :ecto)
    end

    @doc """
    Returns the rows (loaded structs or `{schema, id}` values of one schema) that the actor
    may `action`, in order, duplicates kept. Rows that need the database are decided with
    one query per tenant (`WHERE id = ANY($1) AND scope`).
    """
    @spec filter(Warden.actor_or_context(), atom, [row], opts) :: [row]
    def filter(actor_or_context, action, rows, opts \\ []) when is_list(opts) do
      case Enum.to_list(rows) do
        [] ->
          []

        [first | _rest] = rows ->
          {actor, context, authorizer} = Decision.setup(actor_or_context, opts)
          schema = row_schema!(first)

          if Enum.any?(rows, &(row_schema!(&1) != schema)),
            do: raise(ArgumentError, "Warden.Ecto.filter/4 takes rows of one schema")

          info = Info.policy_for!(authorizer, schema)
          rule = Rule.can(info.policy, action)
          Decision.filter(actor, rule, rows, [authorizer: authorizer, context: context], :ecto)
      end
    end

    @doc """
    Returns the actors (or context maps) in `actors` that may `action` the row, in order.
    One query for all of them: the row selected with every actor's scope as a column.
    For an audience, such as "who may see this comment".
    """
    @spec allowed_actors([Warden.actor_or_context()], atom, row, opts) :: [
            Warden.actor_or_context()
          ]
    def allowed_actors(actors, action, row, opts \\ []) when is_list(actors) and is_list(opts),
      do: Audience.allowed_actors(actors, action, row, opts)

    @doc """
    Explains the decision for one row: every `allow` and `requires` clause (and every key
    in it) with whether it admits or blocks the row, evaluated against the database. A
    `%Warden.Explanation{}` whose `result` is the decision of `scope/4` for the row, and
    whose steps are

        %{rule: {:allow | :requires, action, index}, result: :ok | {:deny, reason},
          steps: [%{rule: clause_part, result: ..., steps: []}]}

    A gate that denies before the clauses (a system actor of another kind, a tenant other
    than the bound one, a `NULL` tenant, a missing row) is one step `%{rule: {:gate,
    reason}}`. A hand-written scope is one step `%{rule: {:scope, action}}`. A struct that
    `all/5` loaded for this actor and action is one step `%{rule: {:admitted_by_scope,
    action}, result: :ok}` after the gates, as `can/2` decides it; pass `{schema, id}` to
    see its clauses. For a delegated actor, `delegator` explains the delegator's side.

    For development tools, tests and audit logs: it runs every clause and one query per
    actor side.
    """
    @spec explain(Warden.actor_or_context(), atom, row, opts) :: Warden.Explanation.t()
    def explain(actor_or_context, action, row, opts \\ []) when is_list(opts) do
      {actor, context, authorizer} = Decision.setup(actor_or_context, opts)
      info = Info.policy_for!(authorizer, row_schema!(row))
      Graph.ensure_valid!(info.policy)
      Explain.explain(info, action, actor, row, context)
    end

    @doc """
    Scopes every Dataloader load of a schema that has a `Warden.Ecto.Policy`, and passes
    other schemas through unchanged:

        Dataloader.Ecto.new(Repo,
          query: &Warden.Ecto.dataloader_query/2,
          default_params: %{warden_actor: actor}
        )

    Params: `:warden_actor` (required: an actor or a context map), `:warden_action`
    (default `:read`), `:warden_authorizer` and `:warden_tenant`. Without
    `:warden_actor` it raises `Warden.PolicyError`, so a load is never unscoped by
    accident. A schema whose policy is an in-memory `Warden.Policy` raises too.
    """
    @spec dataloader_query(Ecto.Queryable.t(), map) :: Ecto.Queryable.t()
    def dataloader_query(queryable, %{warden_actor: actor_or_context} = params) do
      opts = if params[:warden_authorizer], do: [authorizer: params[:warden_authorizer]], else: []
      {actor, context, authorizer} = Decision.setup(actor_or_context, opts)
      query = Ecto.Queryable.to_query(queryable)

      case dataloader_policy(query.from.source, authorizer) do
        nil ->
          queryable

        _policy ->
          action = Map.get(params, :warden_action, @default_action)

          tenant =
            if Map.has_key?(params, :warden_tenant), do: [tenant: params.warden_tenant], else: []

          scope(query, actor, action, [authorizer: authorizer, context: context] ++ tenant)
      end
    end

    def dataloader_query(_queryable, _params) do
      raise Warden.PolicyError, """
      Warden.Ecto.dataloader_query/2 needs a :warden_actor param (Dataloader.Ecto's \
      default_params), so no load runs unscoped\
      """
    end

    # The policy of the load's root: a schema with a policy is scoped, a schema or a table
    # without one passes through, and a root that cannot be classified (a subquery, a
    # fragment) or a bare table that a policy covers raises.
    defp dataloader_policy({table, nil}, authorizer) when is_binary(table) do
      covered? =
        Enum.any?(authorizer.__warden_catalog__().policies, fn policy ->
          Info.ecto_policy?(policy) and Info.fetch!(policy).schema.__schema__(:source) == table
        end)

      if covered? do
        raise Warden.PolicyError, """
        Warden.Ecto.dataloader_query/2 got the table #{inspect(table)} without its schema; \
        load the schema so its policy scopes the load\
        """
      end

      nil
    end

    defp dataloader_policy({_table, schema}, authorizer) when is_atom(schema) do
      case Warden.Policy.policy_for(authorizer, schema) do
        nil ->
          nil

        policy ->
          if not Info.ecto_policy?(policy) do
            raise Warden.PolicyError, """
            #{inspect(policy)} is not a Warden.Ecto.Policy, so it cannot scope Dataloader \
            loads of #{inspect(schema)}\
            """
          end

          policy
      end
    end

    defp dataloader_policy(_source, _authorizer) do
      raise Warden.PolicyError, """
      Warden.Ecto.dataloader_query/2 cannot tell which schema the load reads (a subquery \
      or fragment root), so it refuses to pass it through unscoped\
      """
    end

    if Code.ensure_loaded?(Ecto.Adapters.SQL) do
      alias Ecto.Adapters.SQL
      alias Warden.Ecto.Placeholders

      @doc """
      Returns `{sql, params}` for `scope/4` of `queryable`, for raw SQL such as a
      `COPY` export, so it uses the same condition as every other read. Needs `ecto_sql`.

          {sql, params} = Warden.Ecto.to_sql(MyApp.Issues.Issue, actor, :read, tenant: id)

      Takes the options of `scope/4`, `:repo` (default: the policy's `:repo`) and
      `:param_offset` (default `0`): the placeholders are numbered from
      `$param_offset + 1`, so the SQL can be embedded in a raw query that already uses
      `$1..$param_offset`:

          {sql, params} = Warden.Ecto.to_sql(query, actor, :read, param_offset: 1)
          Repo.query!("SELECT count(*) FROM (\#{sql}) AS scoped WHERE $1", [true | params])

      The offset must equal the number of placeholders the host statement binds, with no
      gaps: Postgres cannot type a placeholder that no expression uses.

      `:bind` (default `%{}`) names values the host statement already binds, as a map of
      its placeholder numbers (`1..param_offset`) to values. A value the scope needs that
      equals (`===`) a bound value uses the host's placeholder instead of a new one and
      is left out of `params`; the scope's other values are numbered from
      `$param_offset + 1` with no gaps:

          ids = from(issue in MyApp.Issues.Issue, select: issue.id)
          bound = %{1 => workspace_id, 2 => user_id}
          opts = [tenant: workspace_id, param_offset: 2, bind: bound]
          {sql, params} = Warden.Ecto.to_sql(ids, actor, :read, opts)

          Repo.query!(
            "SELECT ... FROM issues WHERE workspace_id = $1 AND owner_id = $2 AND id IN (\#{sql})",
            [workspace_id, user_id | params]
          )

      Values are compared as Ecto dumps them for the query, so a value that differs only
      in type (a UUID string where the column is `:binary_id`, which dumps to 16 bytes)
      does not match and stays a new placeholder: never wrong, only not shared. A shared
      placeholder has one type in both statements, so bind the host's value to a
      placeholder of the type the scope compares it with.
      """
      @spec to_sql(Ecto.Queryable.t(), Warden.actor_or_context(), atom, opts) ::
              {String.t(), [term]}
      def to_sql(queryable, actor_or_context, action, opts) when is_list(opts) do
        {repo, scope_opts} = Keyword.pop(opts, :repo)
        {offset, scope_opts} = Keyword.pop(scope_opts, :param_offset, 0)
        {bound, scope_opts} = Keyword.pop(scope_opts, :bind, %{})

        if not (is_integer(offset) and offset >= 0) do
          raise ArgumentError, "`param_offset:` must be a non-negative integer"
        end

        bound!(bound, offset)
        scoped = scope(queryable, actor_or_context, action, scope_opts)
        repo = repo || scoped |> root_schema!() |> policy_repo(actor_or_context, opts)
        {sql, params} = SQL.to_sql(:all, repo, scoped)
        Placeholders.bind(sql, params, offset, bound)
      end

      # `bind:` is a map whose keys are placeholders the host statement binds. The error
      # names the shape of a bad key, never a value.
      defp bound!(bound, offset) when is_map(bound) do
        case Enum.find(Map.keys(bound), &(not (is_integer(&1) and &1 in 1..offset//1))) do
          nil ->
            :ok

          key ->
            raise ArgumentError, """
            `bind:` keys must be placeholder numbers from 1 to `param_offset:` \
            (#{offset}), got: #{Info.shape(key)}\
            """
        end
      end

      defp bound!(bound, _offset) do
        raise ArgumentError, """
        `bind:` must be a map of placeholder numbers to values, got: #{Info.shape(bound)}\
        """
      end

      defp policy_repo(schema, actor_or_context, opts) do
        {_actor, _context, authorizer} =
          Decision.setup(actor_or_context, Keyword.take(opts, [:authorizer]))

        authorizer |> Info.policy_for!(schema) |> Info.repo!()
      end
    end

    @doc """
    Runs `repo.update_all(query, updates, opts)` when `query` was scoped by `scope/4` for
    one of the policy's `write_actions:`, and raises `Warden.PolicyError` otherwise. A
    scope that a later `or_where` widened is refused, and so is a CTE named like a table
    the scope reads.

    It also refuses `set`, `inc`, `push` and `pull` on the policy's `:tenant` field and on
    the fields the write action's clauses go `through:` (foreign keys, and the type and id
    fields of `through_type:`), which would move a row out of the scope that admitted it.
    Every other field is checked before the write only: the scope decides which rows may
    be written, not what they look like afterwards.
    """
    @spec update_all(module, Ecto.Query.t(), keyword, keyword) :: {non_neg_integer, nil | [term]}
    def update_all(repo, query, updates, opts) when is_list(opts) do
      Guard.write!(query, updates, "update_all")
      repo.update_all(query, updates, opts)
    end

    @doc "Like `update_all/4`, for `repo.delete_all(query, opts)`."
    @spec delete_all(module, Ecto.Query.t(), keyword) :: {non_neg_integer, nil | [term]}
    def delete_all(repo, query, opts) when is_list(opts) do
      Guard.write!(query, [], "delete_all")
      repo.delete_all(query, opts)
    end

    defp root_schema!(%Ecto.Query{from: %{source: {_source, schema}}})
         when is_atom(schema) and schema != nil,
         do: schema

    defp root_schema!(%Ecto.Query{}) do
      raise ArgumentError, """
      Warden.Ecto needs a query whose root is an Ecto schema, not a table name, subquery \
      or fragment\
      """
    end

    defp row_schema!(%schema{}), do: schema
    defp row_schema!({schema, _id}) when is_atom(schema), do: schema

    defp row_schema!(other) do
      raise ArgumentError, "expected a loaded struct or {schema, id}, got #{Info.shape(other)}"
    end

    # The root binding carries the policy's `as:` name, which scope dynamics refer to.
    defp named_root!(%Ecto.Query{from: %{as: as}} = query, %{as: as}), do: query

    defp named_root!(%Ecto.Query{from: %{as: nil} = from} = query, %{as: as}) do
      if Map.has_key?(query.aliases, as) do
        raise ArgumentError,
              "the query already has a binding named #{inspect(as)} that is not its root"
      end

      %{query | from: %{from | as: as}, aliases: Map.put(query.aliases, as, 0)}
    end

    defp named_root!(%Ecto.Query{from: %{as: other}}, info) do
      raise ArgumentError, """
      the query's root binding is named #{inspect(other)}, but #{inspect(info.policy)} \
      scopes the binding #{inspect(info.as)}\
      """
    end

    defp as_dynamic(true), do: dynamic(true)
    defp as_dynamic(false), do: dynamic(false)
    defp as_dynamic(%Ecto.Query.DynamicExpr{} = dynamic), do: dynamic

    defp emit_scope(info, action, %Actor{} = actor, tenant, verdict) do
      decision = %{
        layer: :ecto,
        kind: :scope,
        rule: Rule.can(info.policy, action),
        actor: actor,
        tenant: tenant,
        count: 1,
        denied: if(verdict == false, do: 1, else: 0)
      }

      Telemetry.decision(decision)
    end
  end
end
