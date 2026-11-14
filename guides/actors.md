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

A **bound** credential (`tenant:` set) holds no tenant roles in any other tenant
(`tenant_roles/3` is not called for it), `Warden.Actor.tenants/2` lists only its tenant,
and every policy denies values of another tenant, or of no known tenant, before the
policy runs.

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

The tenant of a value comes from `tenant_of/1` when the authorizer defines it, else the
`tenant:` field of the policy registered for the value's struct, else a `:tenant_id`
key. A value without a tenant denies every tenant-role rule.

`tenant_roles/3` runs at most once per actor and tenant. The result is cached in the
actor struct itself, never in the process dictionary or ETS:

- in GraphQL the actor lives for one document execution (one per subscription publish),
  and Warden keeps the updated actor in `resolution.acc`;
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
authorizer; neither may be anonymous or already delegated. `bounds:` is merged into the
actor's `bounds` for policies to read.

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
per value). A single value goes to `check/2` when that has a clause for the name, else
to `check_many/2` with one element.

In GraphQL, an object rule on a single object under a list (each issue's `assignee`) is
decided per parent by default. `use Warden.Absinthe, batch_across_parents: true`
defers those decisions through `Absinthe.Middleware.Batch`, so every parent's value at
one level is decided in one call. Checks deferred this way have no `resolution`.

### Timeouts

`timeout: ms` runs the check (single or batched) in a separate process. When it takes
longer, the process is killed and every value it was asked about is denied with reason
`:unavailable`. A timeout never grants.

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
