# Actors, checks and policies

Warden 0.2 knows more about who asks: what kind of actor it is, how it authenticated,
which roles it holds in each tenant, whether it is the system, and whether it acts on
behalf of someone else. This guide covers those parts, plus checks with options,
reasons and batching, policies, `Warden.explain/3` and telemetry.

Everything here works the same in the core API, `Warden.Plug` and `Warden.Absinthe`.

## The authorizer

```elixir
defmodule MyApp.Authz do
  use Warden.Authorizer,
    roles: [:instance_admin],
    kinds: [:user, :agent, :webhook, :job],
    tenant_roles: [:owner, :admin, :member, :guest],
    tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
    credential_scopes: ["issues:read", "issues:write"],
    policies: [MyApp.Authz.Issues],
    checks: [
      :self,
      email_visible: [batch: true],
      code_readable: [batch: true, timeout: 3_000],
      member: [opts: [role: {:in, [:owner, :admin]}], required: [:role]],
      team: [system_kinds: [:webhook]]
    ]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: user.instance_roles

  @impl true
  def kind(%{agent?: true}, _context), do: :agent
  def kind(_user, _context), do: :user

  @impl true
  def credential(%{api_key: key}),
    do: %Warden.Credential{method: :api_key, scopes: key.scopes, tenant: key.workspace_id}

  def credential(_context), do: nil

  @impl true
  def tenant_roles(user, workspace_id, _context), do: MyApp.Memberships.roles(user, workspace_id)

  @impl true
  def tenants(actor, _context), do: MyApp.Memberships.workspace_ids(actor.subject)
end
```

Every name in a rule is checked against these catalogs: an unknown tenant role, kind,
credential scope, policy or policy action fails compilation in a schema or a plug, and
raises `Warden.PolicyError` in the core API.

## The context of an actor

An actor keeps the context it was built from (`Warden.actor/2`, `Warden.Plug.actor/2`,
GraphQL). When you pass the actor to `Warden.authorize/3`, `Warden.filter/4`,
`Warden.Ecto` or `Warden.redact/3` without `context:`, checks and policies get that
context, as they would have with the context map itself. A `context:` option wins. A
system actor has no context; its checks get `context:` or `%{}`. For a delegated actor
the context is the request's (the agent's) in both passes, see below. `inspect/1` never
shows the context.

## The actor in a GraphQL resolver

Warden builds the actor of a document execution once, from the execution's context,
before the first field resolves, and decides every rule of that execution for it. Every
subscription publish is a new execution and builds a new actor from the subscriber's
context. A resolver gets that actor with `Warden.Absinthe.actor/1`:

```elixir
field :issues, list_of(:issue) do
  resolve fn _args, resolution ->
    actor = Warden.Absinthe.actor(resolution)
    {:ok, Warden.Ecto.all(MyApp.Repo, MyApp.Issues.Issue, actor, :read)}
  end
end
```

The actor is read-only in a resolver. To warm it once per execution (tenants, tenant
roles, `Warden.Ecto.preload_ids/4`), name a function with `warm_actor:`; Warden calls it
right after it builds the actor, and every rule and resolver of the execution then uses
the warmed actor:

```elixir
use Warden.Absinthe, authorizer: MyApp.Authz, warm_actor: &MyApp.Authz.warm/2

# in MyApp.Authz
def warm(actor, context) do
  {tenants, actor} = Warden.Actor.cached_tenants(actor, context)

  actor
  |> Warden.Actor.preload_tenant_roles(tenants, context)
  |> Warden.Ecto.preload_ids(MyApp.Teams.Team, :read)
end
```

It takes `{module, function}` or a `&Module.function/2` capture, and runs once per
execution: before resolution, at the first field rule in the cases below that skip that
step, at subscribe time for the subscription's own checks, and on every subscription
publish. It may only fill the actor's cache: an answer that is not a `%Warden.Actor{}`,
or an actor whose instance, subject, kind, roles, permissions, credential, system flag,
context, delegator or bounds differ from the one it was given, raises
`Warden.PolicyError`.

Use it rather than building an actor from `resolution.context`: rows that
`Warden.Ecto.all/5` loads are trusted by the object rules only for the actor instance
that loaded them (see the policies guide). It raises `ArgumentError` for a schema
without `use Warden.Absinthe`. Absinthe.Plug's batch mode
(`Absinthe.Pipeline.BatchResolver`) and a pipeline that runs resolution with
`plugin_callbacks: false` skip the step that builds the actor; there the first Warden
rule of the execution builds it, and `actor/1` raises `Warden.PolicyError` when called
before any rule ran.

## Kinds

`kind/2` says what the subject is. It must return a kind from `kinds:` (`:user` is
always declared; the default is `:user`). An actor without a subject has kind
`:anonymous`, which cannot be declared.

```elixir
authorize kind(:user)                 # people only, no agents
authorize kind([:user, :agent])
```

`Warden.Actor.kind/1` returns the kind of any actor.

## Credentials

`credential/1` returns a `Warden.Credential`, or `nil` for a full session:

| Field | Meaning |
|---|---|
| `method` | any atom; `:session` is a full session |
| `scopes` | strings from `credential_scopes:` (others are dropped with a warning), or `:all` |
| `tenant` | the tenant the credential is bound to, or `nil` |
| `bounds` | a map for policies; Warden does not read it |

```elixir
authorize session()                       # a session only, no API keys
authorize credential_scope("issues:write") # a session grants every scope
```

An anonymous actor has no session and no scopes.

A **bound** credential (`tenant:` set) stays in its tenant:

- for a value whose tenant (`tenant_of/1`) is known and is another one, every rule leaf
  except `public()` and `covered()` denies with reason `:tenant_binding`: checks, roles,
  permissions, kinds, `session()`, `credential_scope/1`, tenant roles and policies. No
  check, policy or `tenant_roles/3` is called for such a value, and `check_many/2` and
  `allowed_many/4` never receive it;
- for a value whose tenant is unknown (`nil`, such as a GraphQL root value or a map
  without a tenant), the rules decide as for an unbound actor, except `tenant_role`
  and `can`, which deny it;
- `Warden.Actor.tenants/2` lists only its tenant.

A bare id (from a URL or a channel topic) has no tenant Warden can read. Pass the tenant
with the `tenant:` option of `Warden.authorize/3` and friends, `Warden.Plug` (a
function of the conn in `plug Warden.Plug`, a value in `Warden.Plug.authorize/3`) and
`Warden.Phoenix.Channel` (a function of the topic, or a value in `authorize_join/3`). A
bound actor asked about another tenant is then denied with `:tenant_binding` before the
rule runs, `public()` included, and `tenant_role/1` uses that tenant when the value has
none.

A system actor built with `tenant:` is bound the same way.

## Tenant roles

Tenant roles are roles per tenant (a workspace, an organization). `tenant_roles/3`
returns them for one subject and tenant; `tenant_role_hierarchy` expands them like
`role_hierarchy`.

```elixir
object :issue do
  authorize tenant_role(:guest)                                  # the tenant of the issue
end

field :invite, :invitation do
  arg :workspace_id, non_null(:id)
  authorize tenant_role(:admin, tenant: {:arg, [:workspace_id]}) # the tenant from an argument
end
```

`tenant: {:arg, path}` reads the client's arguments, so it is allowed in field and
argument rules only; in an object rule it fails compilation. The same holds for
`can(policy, action, arg: path)`.

The tenant of a value comes from `tenant_of/1` when the authorizer defines it, else the
`tenant:` field of the policy registered for the value's struct, else a `:tenant_id`
key. A value without a tenant denies every tenant-role rule.

`tenant_roles/3` runs at most once per actor and tenant. The result is cached in the
actor struct itself, never in the process dictionary or ETS:

- in GraphQL the actor lives for one document execution (one per subscription publish),
  and Warden keeps the updated actor in `resolution.acc`; to read them once up front,
  warm it with the schema's `warm_actor:` option;
- in the core API one call reads each tenant once; to share the cache across calls,
  warm it with `Warden.Actor.preload_tenant_roles/3` and pass that actor on;
- `Warden.Plug` builds a new actor on every check.

## System actors

Webhooks, jobs and unfurls act as the system, not as a user:

```elixir
actor = Warden.system_actor(MyApp.Authz, kind: :webhook, tenant: workspace.id, bounds: %{team_ids: ids})
```

A system actor has no subject, roles or permissions, is never anonymous, and fails every
`authenticated()`, `role`, `tenant_role`, `permission`, `session()` and
`credential_scope` rule. It passes a `check` only when the check lists its kind in
`system_kinds:` (the check is not called otherwise), a policy only when the policy lists
its kind in `system_kinds:`, and `kind/1` for its own kind. `tenant:` binds it like a
bound credential.

```elixir
authorize any_of([tenant_role(:guest), all_of([kind(:webhook), check(:team)])])
```

## Acting on behalf of someone

An agent acting for a user gets the AND of both actors:

```elixir
actor = Warden.on_behalf_of(agent_actor, user_actor, bounds: %{issue_ids: [issue.id]})
```

Every rule, check and policy decision is evaluated for the agent and for the user, and
both must pass, so delegation never gives more than either actor has. Rules that name
kinds must list both: `kind([:agent, :user])`. Both actors must come from the same
authorizer; neither may be anonymous or already delegated.

`bounds:` only narrows the agent's own bounds (those of its credential included), never
replaces them. For a key both have, two lists give their intersection, equal values
stay, and any other difference raises `ArgumentError`. A key only one of them has is
kept. The delegator keeps its own bounds. `Warden.Actor.tenants/2` of a delegated actor
lists only the tenants both actors have.

Checks run once per actor. `check.actor` is the agent in the first pass and the
delegator in the second, while `check.context` is the request's context in both. So a
check must read the user from `check.actor`, never from the context (such as
`context[:current_user]`): under delegation the context belongs to the request, not to
the actor being decided.

## Checks

### Options

`opts:` declares the options a rule may pass to a check. They are validated wherever
rules are validated:

```elixir
checks: [member: [opts: [role: {:in, [:owner, :admin]}, scope: :string], required: [:role]]]

authorize check(:member, role: :owner)    # ok
authorize check(:member, role: :viewer)   # compile error
```

Types: `:atom`, `:string`, `:integer`, `:boolean`, `:any`, `{:in, list}`,
`{:list, type}`. A check without `opts:` accepts any options.

### Reasons

A check returns `true`, `false` or `{:deny, reason}`, where `reason` is an atom or
`{atom, map}`. Only `true` grants; anything else raises `Warden.PolicyError`.

```elixir
def check(:member, %Warden.Check{actor: actor, value: issue}) do
  case MyApp.Memberships.role(actor.subject, issue.workspace_id) do
    nil -> {:deny, :not_member}
    role when role in [:owner, :admin] -> true
    _role -> {:deny, {:role_too_low, %{needed: :admin}}}
  end
end
```

The reason lands in `Warden.Denial.reason` (a list in rule order for `any_of`), in
`c:Warden.Authorizer.deny/1` and in `Warden.ForbiddenError.denial`. The default denial
handler never puts it in a response. With `expose_denial_reasons: true` it adds the
atom (never the map of an `{atom, map}` reason). `Warden.Denial.trace` lists every leaf
rule evaluated with its result.

### Batching

A check declared with `batch: true` is answered by `check_many/2` for a whole list:

```elixir
@impl true
def check_many(:email_visible, checks) do
  visible = MyApp.Users.visible_email_ids(Enum.map(checks, & &1.value.id))
  Enum.map(checks, &(&1.value.id in visible))
end
```

It returns one `true | false | {:deny, reason}` per check, in order. A wrong length, a
bad element or a raise is a `Warden.PolicyError`; nothing is granted. Warden calls it
once per list for `Warden.filter/4` and for GraphQL lists, also inside
`all_of`/`any_of` (the batched checks are decided for every value first, then the rule
per value). A single value goes to `check_many/2` too, as a one-element list, so a
catch-all `check/2` clause never sees a batched check. To answer single values with
`check/2` instead, declare `single: true` next to `batch: true`:

```elixir
checks: [email_visible: [batch: true, single: true]]
```

In GraphQL, an object rule on a single object under a list (each issue's `assignee`) is
deferred through `Absinthe.Middleware.Batch` by default (`batch_across_parents: :auto`),
so every parent's value at one level is decided in one call. `:auto` does this for rules
with a `batch: true` check or a `can/2` over a policy with `allowed_many/4` (or an Ecto
policy), when the schema has the Batch plugin (Absinthe's default plugins include it).
`batch_across_parents: false` decides per parent; `true` defers every rule with a
batched leaf and fails compilation without the plugin. Checks deferred this way have no
`resolution`.

A check that decides an object from the object alone can say so with `per_object: true`
(`checks: [team: [per_object: true]]`). In an object rule Warden then hands it no
`field`, `args`, `parent_type`, `argument` or `resolution`, and an object rule made of
such checks and built-in leaves is decided once per object and request
(`decision_reuse:`, see the README). The check must answer the same for the same actor,
object and context within one request.

### Timeouts

`timeout: ms` runs the check (single or batched) in a separate process. When it takes
longer, the process is killed and every value it was asked about is denied with reason
`:unavailable`. A timeout never grants. Within one call (`Warden.filter/4`, a GraphQL
list, a delegated actor's two passes), a check that timed out is not called again: it
denies the remaining values with `:unavailable` at once, so a list waits one timeout,
not one per value.

The process gets a copy of the caller's whole process dictionary (a tenant prefix, a
dynamic repo), except keys that are atoms starting with `$`, which belong to the
runtime. `$callers` is set to the caller chain, so test sandboxes that follow it work.
After a kill Warden waits for the process to be gone, so no late answer can arrive.

## Policies

A `Warden.Policy` is one declaration per resource and action, used with `can/2,3`:

```elixir
defmodule MyApp.Authz.Issues do
  use Warden.Policy, authorizer: MyApp.Authz, for: MyApp.Issue, actions: [:read, :write], tenant: :workspace_id

  @impl true
  def allowed?(:read, actor, %MyApp.Issue{} = issue, _context), do: MyApp.Issues.readable?(actor, issue)
  def allowed?(:write, actor, %MyApp.Issue{} = issue, _context), do: issue.author_id == actor.subject.id
  def allowed?(action, actor, {MyApp.Issue, id}, context), do: allowed?(action, actor, MyApp.Issues.get!(id), context)

  @impl true
  def allowed_many(:read, actor, issues, _context), do: MyApp.Issues.readable_many(actor, issues)
  def allowed_many(action, actor, issues, context), do: Enum.map(issues, &allowed?(action, actor, &1, context))
end
```

```elixir
object :issue do
  authorize can(MyApp.Authz.Issues, :read)            # one allowed_many/4 call per list
end

field :update_issue, :issue do
  arg :id, non_null(:id)
  authorize can(MyApp.Authz.Issues, :write, arg: [:id]) # asks about {MyApp.Issue, id}, before the resolver
end
```

See `Warden.Policy` for what Warden decides before calling the policy.

## GraphQL: `covered()` and `on_deny:`

Under `strict_mode: :all` every field needs a rule. `covered()` says "the object rule
guards this field", so `public()` stays for fields that are public on purpose:

```elixir
object :issue do
  authorize can(MyApp.Authz.Issues, :read)
  field :title, :string do
    authorize covered()
  end
end
```

The verifier accepts `covered()` only as a whole field rule on an object type or
interface that has an object rule.

`authorize rule, on_deny: ...` sets the result of a denied field rule for one field:
`:null` (no error; a compile error on a non-null field), `{:replace, value}` or
`:error` (the default, through `deny/1`).

## Explaining a decision

```elixir
%Warden.Explanation{result: :deny, reason: [nil, :not_member], steps: steps} =
  Warden.explain(actor, any_of([role(:instance_admin), check(:member, role: :admin)]), value: issue)
```

`explain/3` evaluates every sub-rule without short-circuiting and returns the tree of
steps, with rule terms only. Its `result` is always the decision `Warden.authorize/3`
makes. Every check in the rule runs, so use it in development tools, tests and audit
logs rather than on every request.

## Telemetry

Warden emits `[:warden, :decision]` once per decision call; a list is one event:

```elixir
:telemetry.attach("warden-denials", [:warden, :decision], &MyApp.Audit.decision/4, nil)

def decision(_event, %{count: count, denied: denied}, metadata, _config) do
  # metadata: %{layer, kind, rule, result, reason, actor_kind, tenant}
end
```

`layer` is `:core`, `:plug` or `:absinthe`. The metadata never holds a subject or a
guarded value, and `reason` is reduced to atoms. See `Warden.Telemetry`.
