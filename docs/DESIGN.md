# absinthe_warden: design

Role- and permission-based authorization for Absinthe. Rules attach to fields, object
types, interfaces, unions, arguments and input fields. Denied data becomes `null` (folded to
the nearest nullable parent), never a failed request. Works the same for queries,
mutations and subscriptions.

Package `absinthe_warden`, top module `Warden`. Absinthe `>= 1.7.0`; primary target 1.12.

## Security goals (the contract)

1. **One choke point.** Every field resolution passes through Warden middleware that the
   library itself attaches at schema compile time. A user's own `middleware/3` cannot
   remove it. A compile-time verifier proves it is present on every field that needs it.
2. **Only literal `true` grants.** A check that returns `:ok`, `{:ok, true}`, `"yes"`,
   `1` or `nil` is not a grant. A non-boolean return raises `Warden.PolicyError`
   (a bug, fail closed). A `false` is a normal denial.
3. **Deny before side effects.** Field and argument rules run before the resolver. A denied
   mutation never runs its resolver.
4. **Deny the whole object.** Object rules null the object itself (or fold upward), so a
   client cannot learn that it exists, not even through `__typename`.
5. **The subscriber's identity, always.** Subscription payloads resolve with the
   subscriber's actor, re-checked on every publish. Never the publisher's, never another
   subscriber's.
6. **Secure defaults for errors.** The default denial error says only `"Forbidden"` with
   `extensions.code = "FORBIDDEN"`. Revealing the missing role or permission is opt-in.
7. **No silent typos.** Rules that name a role or permission absent from the declared
   catalog fail compilation.

Non-goals for v1: hiding fields from introspection output, permission wildcards
(`posts:*`), rate limiting, `@defer`/`@stream`.

## Rules are data

A rule is a plain, escapable Elixir term, so it can live in schema `meta`. Builder
functions in `Warden.Rule` (imported by `Warden.Notation`) produce them:

| Builder | Term | Passes when |
|---|---|---|
| `public()` | `:public` | always |
| `authenticated()` | `:authenticated` | actor has a subject (not anonymous) |
| `role(r)` | `{:role, r}` | actor has role `r` (after hierarchy expansion) |
| `any_role(rs)` | `{:any_role, rs}` | at least one |
| `permission(p)` | `{:permission, p}` | actor has permission `p` |
| `all_permissions(ps)` / `any_permission(ps)` | ... | all / at least one |
| `check(name)` / `check(name, opts)` | `{:check, name, opts}` | `Authorizer.check(name, %Warden.Check{})` returns `true` |
| `all_of(rules)` / `any_of(rules)` | `{:all, rs}` / `{:any, rs}` | all / at least one |
| `deny()` | `:deny` | never |

No `not`. Negated permission checks fail open when the actor data is incomplete.

Rules are validated at compile time: shape, catalog membership for roles and permissions
(when the authorizer declares a catalog), and that every `check` name is handled
(the authorizer declares `checks: [...]`).

Evaluation returns `:ok | {:deny, %Warden.Denial{}}`. The denial carries the failing
sub-rule and the computed `missing_roles` / `missing_permissions` so a custom error
handler can explain it.

## The authorizer (user module)

```elixir
defmodule MyApp.Authz do
  use Warden.Authorizer,
    roles: [:admin, :editor, :viewer],              # catalog; required
    permissions: ["posts:read", "posts:write"],     # catalog; optional (nil = any term)
    role_hierarchy: %{admin: [:editor], editor: [:viewer]},  # admin implies editor implies viewer
    role_permissions: %{admin: :all, editor: ["posts:write"], viewer: ["posts:read"]},
    checks: [:self, :owner]

  @impl true
  def subject(context), do: context[:current_user]          # nil = anonymous

  @impl true
  def roles(user, _context), do: user.roles                 # list of catalog roles

  @impl true                                                 # optional, default []
  def permissions(user, _context), do: user.extra_permissions

  @impl true                                                 # optional
  def check(:self, %Warden.Check{actor: a, value: v}), do: v.id == a.subject.id

  @impl true                                                 # optional
  def deny(%Warden.Denial{} = d), do: {:error, %{message: "Forbidden", code: "FORBIDDEN"}}
end
```

- **Actor.** `%Warden.Actor{subject, roles, permissions}` with `roles` and `permissions` as
  `MapSet`s. Built once per document execution: hierarchy expanded, `role_permissions`
  merged with `permissions/2`, `:all` kept as an explicit grant-everything marker.
- **Strict callback contracts.** `roles/2` and `permissions/2` must return lists, else
  `Warden.PolicyError`. Unknown roles from the user's data are dropped and logged once
  per execution, never granted.
- **Hierarchy** is validated at compile time: no cycles, only catalog roles.
- **Caching.** The actor is cached in `resolution.acc` under a Warden key, which is
  per-execution. Never in the process dictionary: subscription publishing resolves many
  subscribers in one process. MUST VERIFY: whether a stored subscription blueprint carries
  `acc` across publishes. If it does, the cache must not survive into the next publish,
  so a revoked permission applies on the next event.

## Declaring rules in a schema

```elixir
defmodule MyApp.Schema do
  use Absinthe.Schema
  use Warden.Schema, authorizer: MyApp.Authz, strict_mode: false

  object :user do
    authorize any_of([role(:admin), check(:self)])   # object rule
    field :name, :string                              # no rule: inherits visibility
    field :email, :string do
      authorize any_of([role(:admin), check(:self)])  # field rule
    end
  end

  query do
    field :users, list_of(non_null(:user)) do
      authorize authenticated()
      authorize_args include_deleted: role(:admin)    # argument rule
      arg :include_deleted, :boolean, default_value: false
      resolve &Users.list/2
    end
  end
end
```

`authorize/1` and `authorize_args/1` expand to `meta` entries. Rules must also be
declarable through `hydrate/2` for SDL schemas if Absinthe's hydrate supports `meta`
(verify; skip with a documented note if not).

### `strict_mode` (opt-in, default `false`)

Rules are optional by default. A field or type with no rule is allowed.

| Value | Compile-time requirement |
|---|---|
| `false` (default) | none |
| `:root` | every field on the query, mutation and subscription root types declares a rule (`public()` counts) |
| `:all` | every field of every object type declares a rule, introspection excluded |

A missing rule under strict mode is a `CompileError` naming every offending field, not
only the first. `default_object_rule:` (schema option) applies to object types without
their own rule; it is explicit and documented as a footgun when set to `public()`.

## Enforcement model

Warden attaches up to two middleware entries per field, computed at compile time:

- **Pre** (first in the chain). Evaluates, in order:
  1. The parent object's object rule against `resolution.source` (defense in depth: catches
     any value that reached the type without passing an edge check). Skipped on root types,
     where the root type's own object rule applies to every root field instead.
  2. The effective field rule: the field's own rule AND the rule on the same-named field
     of every interface the parent object implements. A client selecting through an
     interface resolves the concrete object's field, so interface rules must be merged in.
  3. Argument and input-field rules. A rule applies when the effective argument value
     (after variables and defaults) is non-nil and differs from the schema default.
     Walk input objects and lists of input objects recursively.

  On denial: the resolver does not run.
- **Post** (last in the chain, after `Absinthe.Resolution` and anything the user added).
  Applies object rules to the resolved value. Unwraps `non_null` and `list_of` (nested
  lists too). For unions and interfaces, determine the concrete type per value with the
  same resolve-type function Absinthe uses, then apply the abstract type's rule AND the
  concrete type's rule. Must see the final value after Dataloader, `Async` and `Batch`.

Fields that need neither entry get none (no rule on the field, its interfaces, its args,
its parent type, and no object rule reachable from its return type). The compile-time
verifier checks the computed plan against the compiled schema in both directions.

### Attaching the middleware

Attach through a mechanism the user's `middleware/3` cannot bypass. Preferred: a schema
pipeline phase (`@pipeline_modifier`) that runs after Absinthe applies `middleware/3`
and wraps every field. If Absinthe's internals do not allow that on every supported
version, fall back to `Warden.Schema` overriding `middleware/3` via `@before_compile`
and wrapping the user's result. Either way the verifier runs at compile time.

Introspection fields (`__schema`, `__type`, `__typename`) get no field rules, but the
schema option `introspection: rule` (default `public()`) guards `__schema` and `__type`.

### Subscriptions

- **Subscribe time.** Wrap every subscription field's `config` so the pre-checks (root
  type rule, field rule, argument rules) run before the user's `config`. A denial returns
  `{:error, denial_error}` so the client cannot subscribe at all.
- **Publish time.** Pre and post middleware run as for queries, with the subscriber's
  context, rebuilding the actor per publish.
- **`context_id` dedup.** Absinthe shares one resolution between subscribers with the same
  `context_id`. If the user's `config` sets `context_id`, Warden appends an actor
  fingerprint (`Authorizer.actor_key/1`, default: hash of subject identity, roles and
  permissions) so subscribers with different access never share a payload.

## Denial handling and null folding

A denial calls `Authorizer.deny/1` with a `%Warden.Denial{kind, rule, failed_rule,
missing_roles, missing_permissions, actor, path, field, parent_type, type, value_index,
argument}`. `kind` is `:field | :object | :argument | :subscribe | :introspection`.
The handler returns one of:

| Return | Effect |
|---|---|
| `{:error, term}` | field becomes `null` with this error (string, map or keyword) |
| `:null` | field becomes `null` with no error (hides existence) |
| `{:replace, value}` | field resolves to `value` (field denials only); object rules still apply to it |

A non-null field that becomes `null` folds to the nearest nullable parent, following the
GraphQL spec through Absinthe's own null propagation. Verify Absinthe does this on every
supported version; if not, Warden folds explicitly.

### Lists

Per-field `list_policy` (meta) with a schema-wide default `:null_item`:

| Policy | Denied item | Item type non-null |
|---|---|---|
| `:null_item` | becomes `null`, error points at the item index | folds to the list field |
| `:filter` | removed; no error unless the handler returns one | removed |
| `:fail_list` | the whole list field is denied | same |

## Testing requirements

- Unit tests per module: rule evaluation, actor building, hierarchy, catalog validation,
  compile-time errors (assert on `CompileError` from compiling test schemas).
- Integration tests through `Absinthe.run/3` for every row of the enforcement model.
- A **side-effect probe**: denied mutations and denied fields must not call their
  resolvers (assert with messages to the test process).
- **Property tests (StreamData)**: random actors against random documents over a test
  schema (aliases, named and inline fragments, interfaces, unions, nested lists, Relay-style
  node lookup). An independent oracle states what the actor may see. Assert that no
  denied value appears anywhere in the response and that every allowed value does.
- **Subscription tests** with an in-test `Absinthe.Subscription.Pubsub` implementation
  (no Phoenix): subscribe-time denial, publish-time revocation, two subscribers with
  different roles on the same topic, and the `context_id` collision case.
- **Adversarial suite** in `test/adversarial/`: one test per attempted bypass, named
  after the attack. Keep the tests that failed and were fixed.
