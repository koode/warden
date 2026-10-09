# warden: design

Role- and permission-based authorization for Absinthe. Rules attach to fields, object
types, interfaces, unions, arguments and input fields. Denied data becomes `null` (folded to
the nearest nullable parent), never a failed request. Works the same for queries,
mutations and subscriptions.

Package `warden` (was `absinthe_warden`), top module `Warden`. Absinthe `~> 1.12`.

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

## Implementation notes

(File references to `lib/warden/*.ex` for the GraphQL layer predate its move under
`lib/warden/absinthe/` and the module rename to `Warden.Absinthe.*`.)

Evidence is from the Absinthe 1.12.0 source (`deps/absinthe`), with 1.7.10 checked for
the same code paths. File references are relative to `deps/absinthe/lib/absinthe/`.
The full suite passed unchanged on both versions; no version-specific code was needed.
Support for Absinthe 1.7 was dropped on 2026-10-09 (requirement now `~> 1.12`); the 1.7.10
references below are kept as history.

### Verified points

**(a) Attaching middleware.** The schema pipeline runs `Phase.Schema.InlineFunctions`
and then `Phase.Schema.Compile` (`pipeline.ex:200-201`). `InlineFunctions` is where the
user's `middleware/3` is applied (`phase/schema/inline_functions.ex:59` calling
`middleware.ex:303`). Pipeline modifiers run in `__after_compile__`
(`schema.ex:397`, `schema.ex:365`, `schema.ex:323`). Warden registers
`@pipeline_modifier Warden.Phase.Attach`, which inserts its phase directly after
`InlineFunctions`: every field's middleware is wrapped after `middleware/3` has run, so
`middleware/3` cannot remove it. Same structure in 1.7.10 (`pipeline.ex:197-198`).
No `@before_compile` fallback is needed.

Adaptation: when `middleware/3` returns something that cannot be escaped (a closure),
`InlineFunctions` stores a shim instead (`inline_functions.ex:64`) that re-expands the
middleware at runtime and *replaces the rest of the chain* (`middleware.ex:268-275`).
Warden replaces that shim with its own shim, which calls Absinthe's and appends the post
middleware again (`lib/warden/middleware.ex`, `shim/2`).

Adaptation: fields whose middleware is exactly `[{MapGet, key}]` skip middleware entirely
(`phase/document/execution/resolution.ex:287`). Fields Warden wraps never match this;
fields with no Warden entry keep the fast path.

Adaptation: the verifier runs as Warden's own `@after_compile`, after Absinthe's, so it
checks the compiled types (including any later user pipeline modifier) against a freshly
computed plan, in both directions.

**(b) `resolution.acc` lifetime.** `acc` starts as `%{}` per execution
(`blueprint/execution.ex:42`) and is carried from field to field
(`resolution.ex:347`). A stored subscription is only `%{initial_phases, source}`
(`subscription.ex:153`); every publish re-runs the pipeline from the source
(`subscription/local.ex:45`), so `acc` (and the cached actor) never survives into the
next publish. The *context* does survive: it is packed with the phase options at
subscribe time (`subscription/pipeline_serializer.ex:9`). The actor is therefore rebuilt
per publish from the subscribe-time context; a revocation applies on the next event only
if `roles/2` / `permissions/2` read current data rather than a user struct frozen in the
context (tested in `test/subscription/subscription_test.exs`).
`Absinthe.Pipeline.BatchResolver` merges `acc` and `context` across documents
(`pipeline/batch_resolver.ex:15-16`); Absinthe's own publisher does not use it, but a
custom `run_docset/3` that does would break per-subscriber identity (listed in README
limits).

**(c) Null propagation.** A field with errors resolves to `nil`
(`resolution.ex:420`), a `nil` in a non-null position gets an error
(`resolution.ex:450-472`) and `propagate_null_trimming` folds it to the nearest nullable
parent (`resolution.ex:476`, `resolution.ex:493`). Warden relies on that for objects and
single-level lists. Adaptation: for nested lists `null_allowed_in_list?/1`
(`resolution.ex:551-565`) only looks at the innermost item type, so a null inner list in
`[[T!]]` nulls the whole field (more than the spec requires, never less). Warden folds
denied list items itself, and for shapes whose innermost item is non-null it reports all
item errors on the field, so they are not dropped by that over-folding.

**(d) Resolve-type for abstract types.** The executor uses
`Type.Union.resolve_type/3` and `Type.Interface.resolve_type/3`
(`resolution.ex:255`, `resolution.ex:259`; `type/union.ex:77`, `type/interface.ex:86`).
Both are public; the post middleware calls the same functions with the resolution
struct. A value whose concrete type resolves to `nil` is denied (fail closed) when any
possible type has a rule.

**(e) Subscription `config` and `context_id`.** `SubscribeSelf` reads `config` through
`Absinthe.Type.function/2` (`phase/subscription/subscribe_self.ex:57-58`), which resolves
`{:ref, module, identifier}` by calling `module.__absinthe_function__(identifier, :config)`
(`type.ex:45`). Warden sets `config` to `{:ref, Warden.Subscription, {...}}` (escapable,
so it survives `Compile`), whose function runs the subscribe-time checks and then the
user's original `config` (or Absinthe's default topic). The subscription id is
`"__absinthe__:doc:#{context_id}:#{document_id}"` with a unique integer when no
`context_id` is set (`subscribe_self.ex:145`, `subscribe_self.ex:149`); on publish only
the first registered document per id is resolved (`subscription.ex:195`,
`subscription.ex:206`) and the result goes to every subscriber of that id. Warden removes
a user-set `context_id` unless the authorizer opts in with `actor_key/2` (see "Red-team
fix round" below).

**(f) `hydrate/2` and meta.** Supported: `{:meta, keyword}`
(`phase/schema/hydrate.ex:71`). It *replaces* the node's meta
(`hydrate.ex:74`). The phase takes a `:hydrator` option (`hydrate.ex:25` in 1.12 and
1.7.10); Warden installs `Warden.Hydrator`, which keeps Warden keys across a later
`{:meta, _}` (see "Red-team fix round").

**(g) Errors at a list item index.** An error map with `path:` is appended to the field
path (`resolution.ex:571-576`), but any error on a field nulls the whole field
(`resolution.ex:420`), and the result phase nulls every node that carries an error
(`phase/document/result.ex:57`). So a field's middleware cannot report an error for one
nullable item without nulling the list. Adaptation: the post middleware records item
errors in `acc`; `Warden.Plugin` (added to the schema's `plugins/0` by
`use Warden.Schema`) inserts `Warden.Phase.ItemErrors` after resolution, which attaches
each error to the already-null item node. When the fold reaches the field itself
(non-null items), the errors go on the field with `path: [index]` suffixes.

### Other mechanism-level adaptations

- **Rules in meta.** `authorize/1`, `authorize_args/1` and `list_policy/1` evaluate their
  argument at compile time and record it with `Absinthe.Schema.Notation.put_attr/2`
  directly. Going through `meta/1` would not work: it runs `Macro.expand/2` on every
  3-tuple (`schema/notation.ex:2465`), and `{:check, name, opts}` looks like AST. Meta
  keys: `:warden_rule`, `:warden_args`, `:warden_list_policy`.
- **Interface fields are not wrapped.** The executor resolves the concrete object's
  field, never the interface's (`resolution/projector.ex:147-151`), which is why
  interface field rules are merged into each implementing object's field.
- **Denial stops the chain.** On a pre denial Warden drops the rest of the field's
  middleware (keeping only its own post entry for `{:replace, value}`), so no user
  middleware, `Absinthe.Subscription` trigger or resolver runs for a denied field, even
  middleware that ignores the resolution state.
- **Post defers behind runtime appends.** If middleware is appended to the chain at
  runtime after Warden's post entry, post moves itself to the end again
  (`test/adversarial/execution_test.exs`, found by the adversarial suite).

### Deviations from the design

- **Interface object rules also apply to implementors reached directly.** An object's
  effective object rule is its own rule (or `default_object_rule`) AND the object rule of
  every interface it implements. Otherwise a client could skip an interface's rule by
  selecting a field typed as the concrete object. Union rules still apply only through
  the union.
- **Argument and input-field rules apply to present values.** The design says a rule
  applies when the value is non-nil and differs from the default. Warden applies it when
  the key is present (`Map.has_key?`) and either there is no declared default (any
  value, `null` included) or the value differs from a declared default. So a client can
  neither send `null` to escape a default such as `status: PUBLISHED` nor send `null` to
  clear a guarded value that has no default.
- **`:filter` with an error.** Absinthe cannot attach an error to an item that is not in
  the list (see (g)), so when the denial handler returns `{:error, term}` for a filtered
  item, that item is kept as `null` with the error (as `:null_item`). The default
  handler returns `:null` for filtered items, so they are removed silently.
- **Subscribe-time denials always refuse.** A subscription cannot be `null`; when the
  handler returns `:null` or `{:replace, _}` for `kind: :subscribe`, the default
  Forbidden error is used.
- **`{:replace, value}` outside field denials** raises `Warden.PolicyError` (a broken
  handler, fail closed).
- **Anonymous actors** (`nil` or `false` subject) get no roles and permissions; `roles/2`
  and `permissions/2` are not called. `:error` / `{:error, _}` raises
  `Warden.PolicyError`.
- **Object denials default to `:null`.** The design's default handler returns the
  Forbidden error for every denial. Object denials (`kind: :object`) now default to
  `:null`, so "denied" and "not found" look the same; field, argument, subscribe and
  introspection denials keep the error.
- **`introspection:` guards `__schema`/`__type` wherever they appear**, and root object
  rules also guard the root's `__typename`, `__schema` and `__type`.
- **Subscribe time also checks value-independent return-type object rules.**
- **Subscription sharing is opt-in** (`actor_key/2`), instead of always appending an
  actor fingerprint.
- **`Warden.Denial` has an extra `list_policy` field**, so a handler can tell filtered
  items apart.
- **Authorizer options** add `expose_denial_reasons` (the opt-in for revealing missing
  roles and permissions) and `spec_compliant_errors` (Absinthe nests every extra key under
  `extensions` in that mode, `phase/document/result.ex:149`).

### Red-team fix round

Three red-team agents attacked the first version (`test/redteam/`,
`test/redteam_exec/`, `test/redteam_fuzz/`). Changes, with the code that implements them
(paths relative to `lib/warden/`):

1. **Introspection fields by GraphQL name** (`plan.ex:14`, `plan.ex:79`). Identifier
   prefixes were used before, so a user field `:__internal` named `"internal"` skipped
   its rules, strict mode and the verifier.
2. **`introspection:` on every `__schema`/`__type`** (`plan.ex:141`). Absinthe adds them
   to every object *named* `Query`/`RootQueryType` (`phase/schema/introspection.ex`), not
   only to the root.
3. **Root object rules guard root introspection** (`plan.ex:130`).
4. **Interface arguments** (`plan.ex:242`, `plan.ex:283`, `plan.ex:219`). Absinthe
   validates a selection through an interface against the interface field's arguments
   and runs the concrete field with them. The argument plan is the union of the object
   field's and every interface field's declarations, with every input-object walk. If
   any declaration has no default, every present value is restricted (an interface
   default that fills an omitted argument included); otherwise a value is restricted
   when it differs from any declared default. (Confirmer fix: dropping the declarations
   without a default let `items(secret: true)` through when only the interface declared
   `secret = true`.) An exact rule ("unrestricted only if the value equals the default
   of the declaration Absinthe used") is not implementable: the projector replaces the
   document's field definition with the concrete one before middleware runs
   (`resolution/projector.ex:151`) and keeps one occurrence of merged same-named
   selections (`rectify_order/1`), so the declaration used cannot be recovered. Warden
   stays fail-closed.
5. **Present-key argument semantics** (`middleware.ex:146-148`).
6. **`resolve_type` outside the declared members** (`plan.ex:420`). Abstract fields carry
   every object type's rule; the post check looks the returned concrete type up there.
   Post middleware is therefore attached to every abstract field once any object rule
   exists.
7. **`:filter` error paths use the output index** (`middleware.ex:426`).
8. **Opt-in subscription sharing** (`authorizer.ex:81`, `authorizer.ex:177`,
   `subscription.ex:171`). Without `actor_key/2` Warden removes the user's `context_id`;
   with it, the returned key (or `nil` to opt out) is appended. The old `actor_key/1`
   fails compilation instead of being ignored.
9. **Value-independent return-type rules at subscribe time** (`plan.ex:489`,
   `subscription.ex:74`): rules without `check(...)` are evaluated with no
   value; the subscription is refused when the return type's rule, or every possible
   concrete type's rule, denies.
10. **`subject/1` contract** (`actor.ex:45`, `actor.ex:49`).
11. **Default object denials are `:null`** (`authorizer.ex:194`).
12. **Mutations guarded only by their return type** stay a documented limit; the attach
    phase prints a compile-time warning for each (`phase/attach.ex:54`). An explicit
    `authorize public()` on the mutation acknowledges it and silences the warning.
13. **Hydrate.** A `rule:` on an argument node is an argument rule (`plan.ex:219`) and is
    validated with the others. `Warden.Hydrator` (`hydrator.ex:13`, installed by
    `phase/attach.ex`) keeps Warden keys across a later `{:meta, _}` and rejects
    conflicting Warden values.
14. **No plugin loop, per-document entries.** `Absinthe.Pipeline.BatchResolver` re-runs
    plugins until they return no phases (`pipeline/batch_resolver.ex`) and shares one
    accumulator between documents. Item errors and folds are therefore recorded as
    markers in `resolution.extensions`, which Absinthe copies onto the field's result
    node, so they live in each document's own result tree (`middleware.ex`,
    `put_marker/3`). The accumulator only carries a `pending` flag. `Warden.Plugin` asks
    for its phase only when no other plugin wants another pass and the flag is set
    (`plugin.ex:28`); the phase collects and strips the markers of its own document and
    clears the flag (`phase/item_errors.ex:23`). Identical documents in one batch each
    get only their own errors and folds. (Confirmer fix: the first version tagged entries
    with the operation struct and drained them all after the first document.)
    Absinthe copies a field's `extensions` onto its list items and into later
    resolutions, so each marker names its owner (the field's response path) and is taken
    only from that node; the phase then applies all entries in one walk over a trie of
    their paths. Cost stays linear (`test/adversarial/cost_test.exs`; the second confirmer
    pass measured 8,000 denied items at 12 s before this, quadratic).
15. **Folding in nested lists.** Absinthe's `propagate_null_trimming` does not reach an
    object two or more list levels deep, so a nulled non-null field left the object with
    a `null` in a non-null field. Warden records every non-null field it nulls inside a
    list (`middleware.ex`, `maybe_record_fold/1`) and `Warden.Phase.ItemErrors` folds it explicitly to the
    nearest nullable position (`phase/item_errors.ex:95`).

## Outside Absinthe: core API and Plug (added 2026-10-09)

The package becomes `warden` (app `:warden`). One authorizer module serves GraphQL and
REST. Absinthe and Plug are optional dependencies.

### Module layout

| Layer | Modules | Needs |
|---|---|---|
| Core | `Warden`, `Warden.Rule`, `Warden.Authorizer`, `Warden.Actor`, `Warden.Check`, `Warden.Denial`, `Warden.PolicyError`, `Warden.ForbiddenError` | nothing |
| Absinthe | `Warden.Absinthe` (was `Warden.Schema`; `use Warden.Absinthe` with the configured default, or `use Warden.Absinthe, authorizer: MyApp.Authz`), `Warden.Absinthe.Notation`, `Warden.Absinthe.Hydrate`, internals under `Warden.Absinthe.*` | `absinthe` |
| Plug | `Warden.Plug` | `plug` |

Optional layers compile only when their dependency is loaded
(`if Code.ensure_loaded?(Absinthe)`). The core must compile and work, with
warnings-as-errors, in a project that has neither dependency.

### Core API (`Warden`)

```elixir
actor = Warden.actor(context)                          # build once per request (default)
actor = Warden.actor(context, authorizer: MyApp.Authz) # explicit authorizer
:ok = Warden.authorize(actor_or_context, rule, value: post)
:ok = Warden.authorize(context, rule, value: post, authorizer: MyApp.Authz)
# -> :ok | {:error, %Warden.Denial{kind: :call}}
Warden.allowed?(actor_or_context, rule, value: post)   # -> boolean
Warden.authorize!(actor_or_context, rule, value: post) # raises Warden.ForbiddenError
Warden.filter(actor_or_context, rule, posts)           # keeps the permitted values

# Every function takes `authorizer: MyApp.OtherAuthz` to override the default.
```

- `actor_or_context` is a `%Warden.Actor{}` or a context map. A map builds the actor
  through the authorizer (same callbacks as for GraphQL).
- An actor built by a different authorizer raises `Warden.PolicyError`.
- The rule is validated against the authorizer's catalog on every call (cheap). An unknown
  role, permission or check raises `Warden.PolicyError`: fail closed, never a silent deny.
- Same evaluation, same strict-boolean contract and same `Warden.Check` struct as the
  Absinthe path (`value` is the resource; GraphQL-only fields are nil).
- `Warden.ForbiddenError` carries the denial and `plug_status: 403`, so Phoenix renders
  it as 403 without Warden depending on Plug. Its message never names the missing
  role or permission unless the authorizer sets `expose_denial_reasons: true`.

### Plug (`Warden.Plug`)

```elixir
import Warden.Rule
plug Warden.Plug, rule: role(:admin)              # default authorizer
plug Warden.Plug, rule: role(:admin), authorizer: MyApp.AdminAuthz

# in a controller action, for a loaded resource:
with {:ok, conn} <- Warden.Plug.authorize(conn, any_of([role(:admin), check(:owner)]), value: post) do
  ...
end

conn = Warden.Plug.authorize!(conn, check(:owner), value: post, authorizer: MyApp.Authz)
```

- `init/1` validates the rule against the authorizer catalog. Phoenix runs `init/1` at
  compile time, so a typo fails compilation.
- The actor is built once per conn and cached in `conn.private[:warden_actor]`, keyed by
  authorizer. Clients cannot write `conn.private`. Nothing is cached across requests or in
  the process dictionary.
- Context from a conn: optional authorizer callback `conn_context(conn)`, default
  `Map.put(conn.assigns, :conn, conn)`, so a `subject/1` that reads `context[:current_user]`
  works for both GraphQL and REST.
- On denial the plug calls optional authorizer callback `deny_conn(conn, denial)`. The
  plug option `on_deny: {mod, fun}` overrides it. The default sends 401 for an anonymous
  actor and 403 otherwise, body `"Forbidden"` / `"Unauthorized"`, and halts. Whatever
  the handler returns, the plug halts the conn: a handler cannot let a denied request
  through by forgetting `halt/1`.
- `Warden.Plug.authorize/3` returns `{:ok, conn}` (actor cached) or `{:error, denial}`
  and does not send a response; `authorize!/3` raises `Warden.ForbiddenError`.

### Default authorizer

```elixir
# config/config.exs
config :warden, authorizer: MyApp.Authz
```

- Every entry point takes an optional authorizer: the `authorizer:` option of the core
  API, `Warden.Plug` and `Warden.Plug.authorize/3`, and `use Warden.Absinthe`. Without
  one, Warden uses the configured default. An explicit option always wins. When the first
  argument is a `%Warden.Actor{}`, its own authorizer is used, and an `authorizer:` option
  that names a different module raises `Warden.PolicyError`.
- The default is read with `Application.compile_env(:warden, :authorizer)` in one core
  function that every layer uses. `use Warden.Absinthe` and Plug `init/1` resolve it at
  compile time anyway; compile_env makes the core agree with them. If `config/runtime.exs`
  sets a different value, Elixir raises at boot instead of letting the layers disagree.
- No authorizer anywhere raises an `ArgumentError` that names the fix
  (`config :warden, authorizer: MyApp.Authz` in config/config.exs). For the Plug and the
  schema this happens at compile time.
- The configured module must `use Warden.Authorizer`; anything else raises at first
  resolution (compile time for the Plug and the schema).

### Implementation notes: core API and Plug

- **Authorizer resolution** is one function, `Warden.resolve_authorizer!/2`
  (`lib/warden.ex`), used by the core API, `Warden.Plug` (in `init/1` and at call time)
  and `use Warden.Absinthe` (at compile time). The default comes from
  `Application.compile_env(:warden, :authorizer)`. `%Warden.Actor{}` gained an
  `authorizer` field, set by `Warden.Actor.build/2`, so the core can check the actor
  against the authorizer it resolves.
- **Optional layers.** `lib/warden/absinthe.ex`, `lib/warden/absinthe/**` and
  `lib/warden/plug.ex` are wrapped in `if Code.ensure_loaded?(Absinthe)` /
  `if Code.ensure_loaded?(Plug)`. `Warden.Check.resolution` is typed `struct() | nil` and
  the Plug callbacks use `struct()`, so the core names no optional module.
  `test/standalone/no_optional_deps_test.exs` (tag `:no_optional_deps`) builds
  throwaway projects without the optional deps, with only `plug`, with only `absinthe`,
  and with only the configured default, compiles them with warnings as errors (and
  asserts Warden's own dependency compile prints no warning) and runs Warden in them.
- **Plug halting.** After the handler runs, the plug takes its return value only if it is
  a conn, sends the default response when nothing was set, sends a set-but-unsent
  response, and halts in every case.

### Deviations: core API and Plug

- **`Warden.filter/4`** is `filter(actor_or_context, rule, values, opts \\ [])`: the rule
  and the values are both positional, as in the design's example.
- **A `context:` option** on the core API gives checks a context when the first argument
  is an actor (`Warden.Plug` passes the conn context this way).
- **`Warden.Plug.actor/2`** (not in the design) returns `{conn, actor}`, with the actor
  cached; useful to pass the actor on to the core API.
- **Hand-built actors are refused.** An `%Warden.Actor{}` whose `authorizer` is `nil` (not
  built by `Warden.actor/2`, `Warden.Plug.actor/2` or GraphQL) raises
  `Warden.PolicyError` in the core API, since it cannot be checked against an
  authorizer.
- **`Warden.Plug.init/1` raises `ArgumentError`** for an unknown role, permission or
  check (it is a configuration error found at compile time); the core API raises
  `Warden.PolicyError` for the same at call time, as designed.
- **A non-module or non-authorizer authorizer raises `ArgumentError`** (the design says
  "raises" without naming the exception), the same exception as a missing authorizer.

