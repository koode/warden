# Policies and Ecto

A policy answers one question per resource and action: may this actor do `action` on
this row? Declare it once, and every surface asks the same declaration: the query that
lists rows, the single check before an update, the filter over rows you already loaded,
the GraphQL object rule, a webhook, an export, a search.

Without it, each surface writes its own condition. The list query hides private teams,
the export copies the condition as a SQL string, the GraphQL object rule only checks
membership, and the one that forgot a condition is the leak.

This guide covers:

* `Warden.Policy`, an in-memory policy for apps without Ecto (REST, plain structs);
* `Warden.Ecto.Policy`, a policy over an Ecto schema that Warden also turns into a
  query scope;
* the `Warden.Ecto` functions: scopes, checks, lists, audiences, explanations, exports,
  Dataloader and guarded writes.

## In-memory policies: `Warden.Policy`

When nothing needs a query (a REST app that loads one struct and checks it), an
in-memory policy is enough. It needs no Ecto.

```elixir
defmodule MyApp.Authz.Docs do
  use Warden.Policy,
    authorizer: MyApp.Authz,
    for: MyApp.Doc,
    actions: [:read, :write],
    tenant: :workspace_id

  @impl true
  def allowed?(:read, actor, %MyApp.Doc{} = doc, _context),
    do: doc.public or doc.author_id == actor.subject.id

  def allowed?(:write, actor, %MyApp.Doc{} = doc, _context),
    do: doc.author_id == actor.subject.id
end
```

The authorizer lists it in `policies:`, and rules use it with `can/2,3`:

```elixir
import Warden.Rule

Warden.authorize(context, can(MyApp.Authz.Docs, :write), value: doc)
Warden.Plug.authorize(conn, can(MyApp.Authz.Docs, :read), value: doc)   # in a controller
```

Move to `Warden.Ecto.Policy` as soon as you list rows from a database: an in-memory
policy can filter rows you loaded, but it cannot tell the database which rows to load.

## Ecto policies: `Warden.Ecto.Policy`

```elixir
defmodule MyApp.Authz.Issues do
  use Warden.Ecto.Policy,
    authorizer: MyApp.Authz,
    schema: MyApp.Issues.Issue,
    as: :issue,
    tenant: :workspace_id,
    repo: MyApp.Repo,
    actions: [:read, :read_trashed, :write],
    write_actions: [:write],
    system_kinds: [:webhook]

  allow :read, through: :team, where: [trashed_at: nil]
  allow :read_trashed, tenant_role(:admin)
  allow :write, rule: tenant_role(:member), through: {:team, :read}, where: [trashed_at: nil]
  requires :write, credential_scope("issues:write")
end
```

Options:

* `schema:` - the Ecto schema, with exactly one primary key field.
* `as:` - the name of the root binding. Hand-written scopes refer to it
  (`dynamic([issue: issue], ...)`), and `Warden.Ecto.scope/4` gives a query's root
  binding this name.
* `tenant:` - the field with the row's tenant (a workspace, an organization). Leave it
  out for a schema without tenants.
* `null_tenant: true` - rows whose tenant field is `NULL` are decided with tenant `nil`.
  By default they are never visible.
* `repo:` - the repo for the queries Warden runs itself (single checks, lists,
  `allowed_actors/4`, `explain/4`, `to_sql/4`). `scope/4` returns a query and needs no
  repo.
* `system_kinds:` - the system actor kinds the policy decides for.
* `subject_id:` - the key of the subject that holds its id (default `:id`), for
  `actor_in:`, `member_of:` and `grant:`.
* `write_actions:` - the actions whose scopes `update_all/4` and `delete_all/3` accept.

The authorizer lists the policy:

```elixir
use Warden.Authorizer,
  tenant_roles: [:owner, :admin, :member, :guest],
  tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
  kinds: [:user, :agent, :webhook],
  credential_scopes: ["issues:read", "issues:write"],
  policies: [MyApp.Authz.Teams, MyApp.Authz.Issues, MyApp.Authz.Comments]
```

Each action gets either a hand-written `scope/4` or declarative clauses, never both
(a compile error).

## Hand-written scopes

`scope(action, actor, tenant, context)` returns an Ecto dynamic over the `as:` binding,
`true` (every row of the tenant) or `false` (none):

```elixir
defmodule MyApp.Authz.Notes do
  use Warden.Ecto.Policy,
    authorizer: MyApp.Authz,
    schema: MyApp.Note,
    as: :note,
    tenant: :workspace_id,
    actions: [:read]

  import Ecto.Query, only: [dynamic: 2]

  @impl true
  def scope(:read, actor, tenant, context) do
    {roles, _actor} = Warden.Actor.tenant_roles(actor, tenant, context)

    cond do
      MapSet.size(roles) == 0 -> false
      MapSet.member?(roles, :admin) -> true
      true -> dynamic([note: note], note.secret == false or note.author_id == ^actor.subject.id)
    end
  end

  # Optional: decide a loaded struct without a query. It must agree with scope/4.
  @impl true
  def allowed?(:read, actor, %MyApp.Note{} = note, context), do: ...
end
```

Anything else than a dynamic, `true` or `false` raises `Warden.PolicyError`. Warden
calls `scope/4` at most once per actor, tenant and action in one call, and never with a
delegated actor (see delegation below). The gates in "Tenants" run first, so the
callback is never asked about a tenant the actor may not act in.

## Clauses

`allow` clauses are ORed. `requires` clauses are ANDed with them (`require` is an Elixir
special form, so the macro is `requires`). The keys inside one clause are ANDed. A bare
rule is short for `rule:`: `requires :read, session()`.

An `allow` clause needs at least one key about the actor: every key but `where:`,
`none:` and `if_nil:`. A clause with `where:` alone would admit every actor, anonymous
ones included; when that is what you mean, say so with `rule: public()`. An action with
`requires` clauses but no `allow` fails compilation, because it would never allow
anything.

### `rule:`

A Warden rule about the actor in the tenant being decided, without the row:

```elixir
allow :read, rule: tenant_role(:member), where: [private: false]
allow :read, rule: any_of([role(:instance_admin), tenant_role(:admin)])
```

`tenant_role/1` reads the tenant being decided. Checks get `value: nil` and the tenant
in `args.tenant`. `can/2,3`, `covered()` and `tenant_role(r, tenant: ...)` fail
compilation.

### `where:`

A field equals a literal; `nil` means `IS NULL`. Values are cast to the field's type at
compile time and always sent as query parameters.

```elixir
allow :read, rule: tenant_role(:member), where: [private: false, trashed_at: nil]
```

### `through:` and `if_nil:`

The `belongs_to` parent is allowed under its own policy, for the same action or the one
you name, and in the same tenant:

```elixir
allow :read, through: :team                  # the team's :read
allow :write, through: {:team, :read}        # the team's :read, for this :write
allow :read, through: :issue, if_nil: :tenant
```

It compiles to `EXISTS (SELECT 1 FROM teams WHERE teams.id = issues.team_id AND
teams.workspace_id = $1 AND <the team's scope>)`, built once per call and tenant. A
`through` never crosses tenants: Warden adds the tenant condition, and a tenanted
schema cannot go through an untenanted one (or the other way round).

A `nil` foreign key denies (`if_nil: :deny`, the default). `if_nil: :tenant` admits it
for actors with any tenant role in the row's tenant.

Options go in a third element (or the second, without an action):
`through: {:team, :read, resolve: :ids, system: :inherit}`.

* `resolve: :ids` runs the parent's scope once per actor, tenant and call, and compares
  the foreign key with the ids it returns: `team_id = ANY($ids)` instead of a correlated
  `EXISTS`. The ids are read from the same tenant, so the tenant condition holds. Use it
  when the parent set is small per actor (the teams a member can see), where it is
  faster than `EXISTS` on large child tables; keep the default for parents an actor sees
  thousands of. The ids are read when the scope is built, so `scope/4` takes `prefix:`
  for a query you will run with a prefix. `to_sql/4` shows the result.

  Each call reads the ids again, so an app that builds several scoped queries per
  request pays one extra query for each, which `EXISTS` does not. To read them once per
  request, preload them into the actor and pass that actor on, as with tenant roles:

  ```elixir
  actor = Warden.Ecto.preload_ids(actor, MyApp.Teams.Team, :read)
  ```

  The cached ids are used only for the same parent, action, tenant (`tenant:`, else
  every tenant of the actor), query prefix and actor; for a delegated actor each side
  keeps its own. They are as fresh as the actor: a team created later in the request is
  not in them, so keep the actor for one request.
* `system: :inherit` makes the clause apply to system actors without its `rule:` naming
  their kind: the parent policy decides them, so the clause admits only the system kinds
  the parent admits (and the child must still list the kind in `system_kinds:`). It
  applies to that clause only.

### `through_any:`

At least one row of a `has_many` or `many_to_many` association is allowed under its own
policy:

```elixir
allow :read, through_any: :teams                     # many_to_many
allow :read, rule: tenant_role(:guest), through_any: {:linked_issues, :read}
allow :read, through_any: {:teams, :read, system: :inherit}
```

`system: :inherit` works as for `through:`: the related policy decides system actors.
`resolve:` is not available here.

### `none:`

The association has no rows at all (any tenant):

```elixir
allow :read, rule: tenant_role(:member), none: :teams
```

Over a `many_to_many` it asks the join table alone (`NOT EXISTS (SELECT 1 FROM
project_teams ...)`), without joining the far table.

### `actor_in:`

One of the fields equals the actor's subject id:

```elixir
allow :read, rule: tenant_role(:guest), actor_in: [:lead_id, :creator_id]
```

Anonymous and system actors have no subject id, so they never pass it.

### `member_of:`

A row in another schema (or table) links this row to the actor:

```elixir
allow :read, member_of: {MyApp.Teams.Membership, :team_id, :user_id}
```

`EXISTS (SELECT 1 FROM team_memberships WHERE team_id = teams.id AND user_id = $1)`.

### `grant:`

An explicit share, with an optional expiry. A share whose `expires_at` is in the past
denies; `NULL` never expires. With `expires_at:` the share must be a schema, not a table
name: Warden sends the current time in the column's own type, so a `timestamptz` column
is compared without the session's time zone getting in the way.

```elixir
allow :read,
  grant: {MyApp.Shares.Share, :issue_id, :grantee_id, expires_at: :expires_at},
  where: [trashed_at: nil]
```

Grants are rows, so revoking one is a delete, and the next query sees it.

### `through_type:`

A polymorphic parent: the type field picks the parent's policy. A type that is not in
the map denies.

```elixir
allow :read,
  through_type:
    {:subject_type, :subject_id,
     %{"project" => MyApp.Authz.Projects, "team" => MyApp.Authz.Teams,
       "comment" => {MyApp.Authz.Comments, :read}}}
```

### `within:`

The field is in the actor's `bounds[key]`. A missing key denies, and a `NULL` field never
matches, even when the bounds hold a `nil`.

For an optional limit, such as a credential that may or may not carry a team limit, opt
in to admitting a missing key; an empty list still admits nothing:

```elixir
allow :read, rule: tenant_role(:member), within: {:team_ids, :id, if_missing: :allow}
```

```elixir
allow :read, rule: kind(:agent), within: {:issue_ids, :id}
```

### `when:`

The escape hatch: a function of the actor, the tenant and the context that returns a
dynamic, `true` or `false`, like `scope/4`:

```elixir
allow :read,
  rule: tenant_role(:admin),
  when: fn actor, _tenant, _context ->
    dynamic([comment: comment], comment.author_id == ^actor.subject.id)
  end
```

A self-referencing hierarchy (a team inside a parent team) needs `when:` with a
recursive CTE: `through:` back to the same schema is a cycle and fails compilation.

### What fails compilation, and what fails on first use

Compilation fails for unknown options, actions, clause keys, fields and associations, a
`through` that is not a `belongs_to`, an association with a `where:` filter, a
`through`/`through_any` back to the same schema,
values that do not cast to their field types, an action with both a `scope/4` clause and
clauses or with neither, and an action with `requires` but no `allow`.

What depends on other policies is only known once they have all compiled: a `through`
to a schema without a `Warden.Ecto.Policy`, a cycle over several policies, a parent of
another authorizer or without the action, and mixed tenancy. Warden checks these after
your project compiles and prints a compiler warning for each (so
`mix compile --warnings-as-errors` fails), and the policy raises `Warden.PolicyError` on
its first use.

## Scopes

```elixir
import Ecto.Query

MyApp.Issues.Issue
|> Warden.Ecto.scope(actor, :read, tenant: workspace.id)
|> where([issue: issue], issue.state == :open)
|> order_by([issue: issue], desc: issue.inserted_at)
|> Repo.all()
```

`scope/4` takes a schema or a query whose root is the policy's schema and adds one
`where`. Pagination, sorting, counts and joins stay yours.

It refuses (`ArgumentError`) what it cannot scope as a whole:

* `union`, `union_all`, `intersect` and `except`: the other arms would stay unscoped.
  Scope each arm, then combine them:

  ```elixir
  open = Warden.Ecto.scope(open_issues, actor, :read)
  recent = Warden.Ecto.scope(recent_issues, actor, :read)
  Repo.all(union_all(open, ^recent))
  ```

* preloads: the children would load without their own policy. Preload a scoped query,
  or load them with `dataloader_query/2`:

  ```elixir
  comments = Warden.Ecto.scope(MyApp.Comment, actor, :read)

  MyApp.Issues.Issue
  |> Warden.Ecto.scope(actor, :read)
  |> preload(comments: ^comments)
  ```

A CTE named like a table the scope reads (`WITH team_memberships AS (...)`) raises
`Warden.PolicyError`: Postgres would read the CTE instead of the table. Other CTEs are
fine.

A query run with a prefix (`Repo.all(query, prefix: "tenant_b")`) reads every table of
the scope in that prefix. Single checks and lists decide a struct against the prefix it
was loaded from (`__meta__.prefix`). Every function takes an actor
or a context map, and `authorizer:` like the core API.

## Tenants

* With `tenant: t`, the scope covers the rows of tenant `t`.
* Without it, the scope covers every tenant from `c:Warden.Authorizer.tenants/2`:
  `(workspace_id = $1 AND scope_1) OR (workspace_id = $2 AND scope_2) ...`, with the
  tenants whose scope is `true` merged into one `workspace_id = ANY($n)`.

Before a policy is asked about a tenant, Warden denies:

* a system actor whose kind is not in `system_kinds:`;
* a `NULL` tenant, unless the policy sets `null_tenant: true`;
* a tenant other than the one the actor's credential is bound to (and every row of an
  untenanted schema, which belongs to no tenant);
* a tenant that is not one of the actor's (`Warden.Actor.tenants/2`).

The last one keeps every answer the same: a single check never admits a row that the
scope over every tenant of the actor would leave out. So `tenants/2` must list every
tenant the actor may act in, and it runs (once per actor and call) even when you pass
`tenant:` or check a single row; keep it cheap, or cache it in the context. An anonymous actor has no tenants, so it sees no rows of a
tenanted schema; serve public pages from an untenanted schema or with a system actor.

## System actors and webhooks

A system actor (`Warden.system_actor/2`) passes only `allow` clauses whose `rule:` names
its kind, and only in a policy with that kind in `system_kinds:`. `requires` clauses
still apply. A webhook bound to one workspace, limited to some teams:

```elixir
hook = Warden.system_actor(MyApp.Authz, kind: :webhook, tenant: workspace.id, bounds: %{team_ids: team_ids})

# in MyApp.Authz.Teams
allow :read, rule: kind(:webhook), within: {:team_ids, :id}

# in MyApp.Authz.Issues
allow :read, rule: kind(:webhook), through: :team, where: [trashed_at: nil]

Warden.Ecto.allowed?(hook, :read, issue)
```

When a child should follow its parent for system actors, `through: {:team, :read,
system: :inherit}` saves naming the kinds again (see `through:`). To name them once, keep
them in a module attribute set before `use`; options and clause values read it:

```elixir
@system_kinds [:automation, :unfurl]

use Warden.Ecto.Policy, ..., system_kinds: @system_kinds

allow :read, rule: kind(@system_kinds), through: :team
```

## Delegation

For an actor acting on behalf of another (`Warden.on_behalf_of/3`), every scope and
check is the AND of both actors', over the tenants both are in. It is never wider than
either. Bounds given to `on_behalf_of/3` reach the acting actor's `within:` clauses:

```elixir
effective = Warden.on_behalf_of(agent, user, bounds: %{issue_ids: [issue.id]})
Warden.Ecto.scope(MyApp.Issues.Issue, effective, :read)
```

## Single checks and lists

```elixir
Warden.Ecto.allowed?(actor, :write, issue)                   # a loaded struct
Warden.Ecto.allowed?(actor, :write, {MyApp.Issues.Issue, id}) # by id
Warden.Ecto.authorize(actor, :write, issue)                  # :ok | {:error, %Warden.Denial{}}
Warden.Ecto.filter(actor, :read, issues)                     # order and duplicates kept
```

For a loaded struct, a hand-written `allowed?/4` answers when the policy has one.
Otherwise Warden decides from the clauses in memory where that is exact, and asks the
database for the rest:

* exact in memory: `rule:`; `where:`, `actor_in:` and `within:` on ids, integers,
  booleans, strings and enums; `through:` with the parent preloaded; `through_any:` over
  a `has_many` when a preloaded child that points at the row is allowed; `through_type:`
  with a type outside the map;
* always the database: `none:`, `member_of:`, `grant:`, `when:`, `scope/4` and
  `through_any:` over a `many_to_many` (a preload may have been filtered, and link rows
  are not loaded).

The database part is one query per tenant: `WHERE id = ANY($1) AND workspace_id = $2
AND scope`. `{schema, id}` values are one query inside the scope of every tenant of the
actor. In-memory answers trust the struct: a struct you changed but did not save is
decided as it is. A struct loaded with a partial `select` has `nil` in the columns it did
not load, so a clause that would admit because of a `nil` (`where: [trashed_at: nil]`, a
`nil` foreign key under `if_nil: :tenant`) is never decided in memory: the database
decides those rows.

In GraphQL, `can(MyApp.Authz.Issues, :read)` as an object rule asks the same policy,
once per list and tenant. `can(MyApp.Authz.Issues, :write, arg: [:id])` decides before
the resolver runs.

Rows a resolver loaded through `scope/4` are decided again by a `can/2` object rule:
Warden does not know that a query was scoped, so the rule runs as for any other value,
with one query per list (and tenant) for the clauses it cannot decide in memory. Preload
the `through:` parent in the resolver's query (`preload: [:team]`) and Warden decides
those rows in memory, without that query.

## Audiences

`Warden.Ecto.allowed_actors(actors, :read, comment)` returns the actors that may see one
row, with one query: the row selected with every actor's scope as a column. For small
audiences, such as the people to notify.

## Dataloader

```elixir
Dataloader.Ecto.new(Repo,
  query: &Warden.Ecto.dataloader_query/2,
  default_params: %{warden_actor: actor}
)
```

Every load of a schema with a `Warden.Ecto.Policy` is scoped (`:read` by default, or
`warden_action:`), and schemas without a policy pass through. Without `warden_actor`
the query function raises, so a load is never unscoped by accident, and so does a root
it cannot classify (a subquery or a fragment) or a bare table name that a policy covers.

## Exports

`to_sql/4` (needs `ecto_sql`) returns the scoped query as SQL and parameters, for a
`COPY` or another raw-SQL export that must use the same condition:

```elixir
query = from(issue in MyApp.Issues.Issue, select: [issue.id, issue.title])
{sql, params} = Warden.Ecto.to_sql(query, actor, :read, tenant: workspace.id)
```

To embed the SQL in a raw statement with its own placeholders, pass `param_offset:`
(the number of placeholders the host statement binds, with no gaps): the scope's
placeholders then start at `$param_offset + 1`. When the host already binds a value the
scope needs, such as the tenant or the user id, name it in `bind:` and the scope uses
the host's placeholder instead of adding the value again:

```elixir
query = from(issue in MyApp.Issues.Issue, select: issue.id)
bound = %{1 => workspace.id, 2 => user.id}
opts = [tenant: workspace.id, param_offset: 2, bind: bound]
{sql, params} = Warden.Ecto.to_sql(query, actor, :read, opts)

Repo.query!(
  "SELECT ... FROM issues WHERE workspace_id = $1 AND author_id <> $2 AND id IN (#{sql})",
  [workspace.id, user.id | params]
)
```

A value is shared only when it equals (`===`) the scope's value as Ecto dumps it for
the query. A value that differs in type (a UUID string where the column is a
`:binary_id`, which dumps to 16 bytes) does not match, and the scope keeps its own
placeholder for it: the SQL is still right, the value is only passed twice.

## Search

Scope every source of a search before you combine them, so each hit type uses its own
policy:

```elixir
issues = MyApp.Issues.Issue |> Warden.Ecto.scope(actor, :read) |> where(^matches) |> select(...)
comments = MyApp.Comment |> Warden.Ecto.scope(actor, :read) |> where(^matches) |> select(...)
Repo.all(union_all(issues, ^comments))
```

## Writes

Give writes their own action, scope with it, and run `update_all` and `delete_all`
through Warden:

```elixir
MyApp.Issues.Issue
|> Warden.Ecto.scope(actor, :write)
|> where([issue: issue], issue.id in ^ids)
|> then(&Warden.Ecto.update_all(Repo, &1, [set: [state: :closed]], []))
```

`update_all/4` and `delete_all/3` raise `Warden.PolicyError` for a query that `scope/4`
did not scope for one of the policy's `write_actions:`, that a later `or_where` widened,
or that has a CTE named like a table the scope reads.

`update_all/4` also refuses `set`, `inc`, `push` and `pull` on the policy's `tenant:`
field and on the fields the write action's clauses go `through:` (the foreign keys, and
the type and id fields of `through_type:`): those would move a row out of the scope
that admitted it, for example into another tenant. Every other field is checked before
the write only: the scope decides which rows may change, not what they hold afterwards.

## Explaining a decision

```elixir
%Warden.Explanation{result: :deny, steps: steps} = Warden.Ecto.explain(actor, :read, issue)
```

Every clause and every key in it, evaluated for that row against the database: which
`allow` admits the row, which `requires` blocks it, or which gate denied it before the
policy was asked. For development tools, tests and audit logs, not for every request.

## Indexes

Every `through:` is an `EXISTS` on the parent's primary key and tenant, every
`through_any:`, `none:`, `member_of:` and `grant:` an `EXISTS` on the child's foreign
key. Index those:

* the foreign key of every `through:` (`issues.team_id`) and the tenant field of every
  policy (`issues.workspace_id`), often together;
* the foreign key of every `through_any:`, `none:` and many-to-many join table
  (`project_teams.project_id`);
* the link fields of `member_of:` and `grant:` (`team_memberships (team_id, user_id)`,
  `shares (issue_id, grantee_id)`).

`to_sql/4` shows the SQL a scope produces, for `EXPLAIN`.
