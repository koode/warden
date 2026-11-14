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
functions in `Warden.Rule` (imported by `Warden.Absinthe.Notation`) produce them:

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
  use Warden.Absinthe, authorizer: MyApp.Authz, strict_mode: false   # explicit
  # use Warden.Absinthe, strict_mode: false   # or the configured default:
  #                                           # config :warden, authorizer: MyApp.Authz

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
version, fall back to `Warden.Absinthe` overriding `middleware/3` via `@before_compile`
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
`@pipeline_modifier Warden.Absinthe.Phase.Attach`, which inserts its phase directly after
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
(`type.ex:45`). Warden sets `config` to `{:ref, Warden.Absinthe.Subscription, {...}}` (escapable,
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
1.7.10); Warden installs `Warden.Absinthe.Hydrator`, which keeps Warden keys across a later
`{:meta, _}` (see "Red-team fix round").

**(g) Errors at a list item index.** An error map with `path:` is appended to the field
path (`resolution.ex:571-576`), but any error on a field nulls the whole field
(`resolution.ex:420`), and the result phase nulls every node that carries an error
(`phase/document/result.ex:57`). So a field's middleware cannot report an error for one
nullable item without nulling the list. Adaptation: the post middleware records item
errors in `acc`; `Warden.Absinthe.Plugin` (added to the schema's `plugins/0` by
`use Warden.Absinthe`) inserts `Warden.Absinthe.Phase.ItemErrors` after resolution, which attaches
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
    validated with the others. `Warden.Absinthe.Hydrator` (`hydrator.ex:13`, installed by
    `phase/attach.ex`) keeps Warden keys across a later `{:meta, _}` and rejects
    conflicting Warden values.
14. **No plugin loop, per-document entries.** `Absinthe.Pipeline.BatchResolver` re-runs
    plugins until they return no phases (`pipeline/batch_resolver.ex`) and shares one
    accumulator between documents. Item errors and folds are therefore recorded as
    markers in `resolution.extensions`, which Absinthe copies onto the field's result
    node, so they live in each document's own result tree (`middleware.ex`,
    `put_marker/3`). The accumulator only carries a `pending` flag. `Warden.Absinthe.Plugin` asks
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
    list (`middleware.ex`, `maybe_record_fold/1`) and `Warden.Absinthe.Phase.ItemErrors` folds it explicitly to the
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
# Each call twice: with the configured default, then with an explicit authorizer.
actor = Warden.actor(context)                                    # build once per request
actor = Warden.actor(context, authorizer: MyApp.Authz)

:ok = Warden.authorize(actor_or_context, rule, value: post)      # -> :ok | {:error, %Warden.Denial{kind: :call}}
:ok = Warden.authorize(actor_or_context, rule, value: post, authorizer: MyApp.Authz)

Warden.allowed?(actor_or_context, rule, value: post)             # -> boolean
Warden.allowed?(actor_or_context, rule, value: post, authorizer: MyApp.Authz)

Warden.authorize!(actor_or_context, rule, value: post)           # raises Warden.ForbiddenError
Warden.authorize!(actor_or_context, rule, value: post, authorizer: MyApp.Authz)

Warden.filter(actor_or_context, rule, posts)                     # keeps the permitted values
Warden.filter(actor_or_context, rule, posts, authorizer: MyApp.Authz)
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
plug Warden.Plug, rule: role(:admin)                            # default authorizer
plug Warden.Plug, rule: role(:admin), authorizer: MyApp.Authz   # explicit

# in a controller action, for a loaded resource (default, then explicit):
with {:ok, conn} <- Warden.Plug.authorize(conn, any_of([role(:admin), check(:owner)]), value: post) do
  ...
end

with {:ok, conn} <- Warden.Plug.authorize(conn, check(:owner), value: post, authorizer: MyApp.Authz) do
  ...
end

conn = Warden.Plug.authorize!(conn, check(:owner), value: post)
conn = Warden.Plug.authorize!(conn, check(:owner), value: post, authorizer: MyApp.Authz)
```

- `init/1` validates the rule against the authorizer catalog. Phoenix runs `init/1` at
  compile time, so a typo fails compilation.
- No actor cache: every Plug check (`call/2`, `authorize/3`, `authorize!/3`) builds the
  actor from the current conn context, so `conn_context/1`, `subject/1`, `roles/2` and
  `permissions/2` run on every check. Nothing is stored in `conn.private` or the process
  dictionary. Reuse within a request is explicit: build the actor once with
  `Warden.actor/2` or `Warden.Plug.actor/2` and pass it to the core API, which freezes
  the roles for as long as the caller holds it.
- Context from a conn: optional authorizer callback `conn_context(conn)`, default
  `Map.put(conn.assigns, :conn, conn)`, so a `subject/1` that reads `context[:current_user]`
  works for both GraphQL and REST.
- On denial the plug calls optional authorizer callback `deny_conn(conn, denial)`. The
  plug option `on_deny: {mod, fun}` overrides it. The default sends 401 for an anonymous
  actor and 403 otherwise, body `"Forbidden"` / `"Unauthorized"`, and halts. Whatever
  the handler returns, the plug halts the conn: a handler cannot let a denied request
  through by forgetting `halt/1`.
- `Warden.Plug.authorize/3` returns `{:ok, conn}` (conn unchanged) or `{:error, denial}`
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
- **No Plug actor cache** (decided after two confirmer rounds). A per-conn cache kept
  failing open when the context changed under it (a subject swap first, then a tenant
  switch with the same subject). Every Plug check now builds the actor from the current
  conn; REST requests run one to three checks. `on_deny: {mod, fun}` is checked in
  `init/1` (`mod.fun/2` must exist, except for a module still being compiled).
- **Inspect hardening.** `Warden.Actor` (custom `Inspect`: authorizer, anonymous, roles,
  permissions), `Warden.Denial` (derived: kind, failed_rule, missing roles and
  permissions, path, field, parent_type, type) and `Warden.ForbiddenError` (message,
  plug_status) never show the subject or the guarded resource.
- **Plug halting.** After the handler runs, the plug takes its return value only if it is
  a conn, sends the default response when nothing was set, sends a set-but-unsent
  response, and halts in every case.

### Deviations: core API and Plug

- **`Warden.filter/4`** is `filter(actor_or_context, rule, values, opts \\ [])`: the rule
  and the values are both positional, as in the design's example.
- **A `context:` option** on the core API gives checks a context when the first argument
  is an actor (`Warden.Plug` passes the conn context this way).
- **`Warden.Plug.actor/2`** (not in the design) returns a freshly built actor and stores
  nothing; useful to pass one actor to several core API calls.
- **Hand-built actors are refused.** An `%Warden.Actor{}` whose `authorizer` is `nil` (not
  built by `Warden.actor/2`, `Warden.Plug.actor/2` or GraphQL) raises
  `Warden.PolicyError` in the core API, since it cannot be checked against an
  authorizer.
- **`Warden.Plug.init/1` raises `ArgumentError`** for an unknown role, permission or
  check (it is a configuration error found at compile time); the core API raises
  `Warden.PolicyError` for the same at call time, as designed.
- **A non-module or non-authorizer authorizer raises `ArgumentError`** (the design says
  "raises" without naming the exception), the same exception as a missing authorizer.


## v0.2.0: actors, policies, scoping, redaction (added 2026-11-14)

Warden 0.1 decides about one value inside GraphQL or one REST call. 0.2 adds the
questions a large Phoenix and Ecto app asks everywhere else: which rows may this actor
see, which fields of a loaded struct may it read, and who is this actor (a user, an
agent, an API key, the system). One declaration per resource then serves GraphQL, REST,
contexts, search, exports, webhooks, jobs and channels.

### Compatibility

Every 0.1 public function, option, callback and rule term keeps working with the same
meaning. In particular: the `{:check, name, opts}` term; `checks:` as a list of atoms;
`Warden.PolicyError` for any check result that is not a grant or a denial; `%Warden.Check{}`
fields `value`, `args`, `context`, `opts`; field and argument rules before the resolver;
`deny/1` returning `:null` for `kind: :field`; `Warden.Authorizer.default_deny/2`;
`roles/2` receiving the context; subscription dedup only with `actor_key/2`;
`use Warden.Absinthe.Notation`; middleware after the app's own `middleware/3`; inspect
output that never shows a subject or a guarded value; the optional dependencies.

### Security goals added in 0.2

8. **One declaration per resource and action.** The query scope, the single check, the
   filter over loaded rows and the GraphQL object rule come from the same policy, and
   Warden ships the tests that prove they agree.
9. **No ambient authority.** A system actor (webhook, job, unfurl) is never anonymous and
   never a user. It passes no role, tenant role, permission, `authenticated()` or check
   rule, and no policy clause, that does not name its kind.
10. **Delegation never widens.** An actor acting on behalf of another gets the AND of both
    actors' decisions, inside explicit bounds.
11. **Bound credentials stay bound.** For an actor bound to tenant A (a credential with
    `tenant: A`, or a system actor built with `tenant: A`) and a value whose tenant
    (`tenant_of/1`) is known and is not A, every rule leaf except `public()` and
    `covered()` denies with reason `:tenant_binding`: checks, roles, permissions, kinds,
    `session()`, `credential_scope/1`, tenant roles and policies alike. No user code is
    called for it, and the batched pre-pass leaves such values out, so `check_many/2` and
    `allowed_many/4` never receive them. A value whose tenant is unknown (`nil`, such as a
    GraphQL root value) is decided as for an unbound actor, except by `tenant_role` and
    `can`, which deny it. Every policy and scope for another tenant is `false`.
12. **Fail closed everywhere new.** A batch callback with a wrong length, a bad value, a
    raise or a timeout denies. A scope callback that returns anything but a dynamic,
    `true` or `false` raises `Warden.PolicyError`. A timeout never grants.
13. **Reasons stay private by default.** Denial reasons, traces and telemetry never carry a
    subject or a guarded value, and the default `deny/1` never puts a reason in a response.

### Module layout added in 0.2

| Layer | Modules | Needs |
|---|---|---|
| Core | `Warden.Credential`, `Warden.Explanation`, `Warden.Policy` (behaviour + `use`), `Warden.Fields` | `telemetry` (required dep) |
| Ecto | `Warden.Ecto`, `Warden.Ecto.Policy`, internals under `Warden.Ecto.*` | `ecto` (`to_sql/4`: `ecto_sql`) |
| Absinthe | `redact_with`, `authorize/2` (`on_deny:`), `covered()`, `can/2,3` | `absinthe` |
| Phoenix | `Warden.Phoenix.Channel` | `phoenix` |
| Test | `Warden.Test`, `Warden.Test.Matrix`, `Warden.Test.Absinthe`, `mix warden.matrix` | ExUnit; Ecto parts need `ecto` |

New optional layers compile only when their dependency is loaded, like Absinthe and Plug,
and the `:no_optional_deps` suite proves it. User guides go in `guides/*.md` (one per
layer: `actors`, `policies-and-ecto`, `fields`, `channels`, `testing`), listed in the
ExDoc extras; the README gets a short section per layer that links to its guide.

### Actors

New fields on `%Warden.Actor{}`: `kind` (atom), `credential` (`%Warden.Credential{}` or
`nil`), `system?` (boolean), `delegator` (an actor or `nil`), `bounds` (map, opaque to
Warden, read by policies), and a private per-actor cache.

Authorizer options and callbacks:

    use Warden.Authorizer,
      roles: [:instance_admin],
      tenant_roles: [:owner, :admin, :member, :guest],
      tenant_role_hierarchy: %{owner: [:admin], admin: [:member], member: [:guest]},
      kinds: [:user, :agent, :system, :webhook],
      credential_scopes: ["issues:read", "issues:write"],
      policies: [MyApp.Authz.Issues, ...],
      checks: [...]

    @callback kind(subject, context) :: atom               # optional, default :user
    @callback credential(context) :: Warden.Credential.t() | nil   # optional, nil = full session
    @callback tenant_roles(subject, tenant_id, context) :: [atom]  # required when tenant_roles: is set
    @callback tenant_of(value) :: term | nil                # optional, see below
    @callback tenants(Actor.t(), context) :: [term]         # optional, for scopes across tenants

* `kind`: `:anonymous` for a `nil`/`false` subject (reserved, not declarable).
  `kind/2` must return a declared kind, else `Warden.PolicyError`. `:user` is always
  declared.
* `%Warden.Credential{method: atom, scopes: [String.t()] | :all, tenant: term | nil,
  bounds: map}`. `method: :session` (or a `nil` credential) is a full session. `tenant`
  binds the credential: for any other tenant, `tenant_roles/3` is not called and the
  actor has no tenant roles, `tenants/2` is narrowed to it, and every policy and scope
  for another tenant is `false`. Scopes must be in `credential_scopes` when that catalog
  is set (unknown ones are dropped with a warning, like roles).
* `tenant_roles/3` runs at most once per actor and tenant: the result is kept in the
  actor's cache. The cache lives in the actor struct only (no process dictionary, no
  ETS), so it never outlives the actor; an actor rebuilt per subscription publish or
  channel push starts empty. In Absinthe the updated actor is written back to
  `resolution.acc`.
* `tenant_of(value)`: where the tenant of a value is. Default: the policy's `tenant:`
  field when a policy is registered for the struct, else a `:tenant_id` key, else `nil`.
  `nil` denies every tenant-role rule.
* `Warden.system_actor(authorizer, kind: k, tenant: t, bounds: map, reason: atom)`:
  `k` must be a declared kind other than `:user` and `:anonymous`. `system?` is `true`, `subject` is `nil`, `anonymous?/1` is
  `false`. `tenant` binds it like a credential.
* `Warden.on_behalf_of(actor, delegator, bounds: map)`: both actors from the same
  authorizer, neither anonymous, the delegator not itself delegated. Every rule, check,
  policy decision and scope is evaluated for both and ANDed. The given bounds only
  narrow the actor's own (its credential's included): for a key in both, two lists give
  their intersection, equal values stay, any other difference raises `ArgumentError`;
  a key in only one is kept. `tenants/2` of a delegated actor is the intersection of
  both actors' tenants.
* `inspect/1` shows `kind`, `system?`, the credential method and scopes, and the
  delegator's kind. Never a subject, never bounds.
* `default_actor_key/1` also covers `kind`, the credential (method, scopes, tenant),
  `system?` and the delegator.

### Rule terms added in 0.2

| Builder | Term | Passes when |
|---|---|---|
| `covered()` | `:covered` | always; accepted only on fields of an object type that has an object rule (verifier), so reviewers can tell "the object rule guards this" from `public()` |
| `tenant_role(r)` / `tenant_role(r, tenant: src)` | `{:tenant_role, r, opts}` | the actor has `r` (after `tenant_role_hierarchy`) in the tenant of the value; `src` is `:value` (default, through `tenant_of/1`) or `{:arg, path}` |
| `kind(k)` / `kind([k, ...])` | `{:kind, [k, ...]}` | the actor's kind is one of them (for a delegated actor: both kinds) |
| `credential_scope(s)` | `{:credential_scope, s}` | the credential grants `s`; a session grants every scope |
| `session()` | `:session` | the credential is a session |
| `can(policy, action)` / `can(policy, action, arg: path)` | `{:can, policy, action, opts}` | the policy allows `action` on the value; with `arg:`, on `{schema, id}` from that argument path, before the resolver |

Unknown tenant roles, kinds, credential scopes, policies and policy actions in a rule fail
compilation (catalog validation, as for roles). The leaves that read field arguments
(`tenant: {:arg, path}`, `arg: path`) are allowed in field and argument rules only. System
actors fail every
`authenticated()`, `role`, `tenant_role`, permission and check rule (see checks below).

### Checks: options, reasons, batching

`checks:` accepts atoms (0.1) and `name: opts` entries:

    checks: [
      :self,
      email_visible: [batch: true],
      code_readable: [batch: true, timeout: 3_000],
      member: [opts: [role: {:in, [:owner, :admin]}, scope: :string], required: [:role]],
      team: [system_kinds: [:webhook]]
    ]

* `opts:` is a schema for the check's rule options, validated wherever rules are
  validated (Absinthe compile time, `Warden.Plug.init/1`, the core API). Types:
  `:atom`, `:string`, `:integer`, `:boolean`, `:any`, `{:in, list}`, `{:list, type}`.
  Unknown keys and missing `required:` keys fail. A check without `opts:` accepts any
  options (0.1 behaviour).
* `system_kinds:` the system kinds the check is called for. For every other system actor
  the check denies without being called.
* A check returns `true`, `false` or `{:deny, reason}` (`reason`: atom or
  `{atom, map}`). Only `true` grants. Anything else raises `Warden.PolicyError`.
* `batch: true`: the authorizer must define `check_many(name, [Check.t()])`, returning a
  list of the same length and order with `true | false | {:deny, reason}`. Warden calls it
  for list items in GraphQL, `Warden.filter/4`, `Warden.redact/3` over lists, and the
  Ecto layer. Wrong length, a bad element or a raise: `Warden.PolicyError`. A single
  value of a batched check goes to `check_many/2` as a one-element list, unless the check
  declares `single: true` (only valid with `batch: true`), which routes single values to
  `check/2`.
* `timeout:` (ms) runs the check (single or batch) in a task. On timeout every value
  denies with reason `:unavailable`. Never grants.
* Inside `all_of`/`any_of` over a list, Warden evaluates the batched checks for all values
  once, then evaluates the rule per value from those results. Short-circuiting is kept
  for unbatched rules.
* Cross-parent batching in Absinthe (object rules on single-object fields under a list,
  deferred through `Absinthe.Middleware.Batch`) is opt-in in 0.2:
  `use Warden.Absinthe, batch_across_parents: true`. Default off: it touches the
  item-error phase and the batch resolver, which is where 0.1's red-team found a hang.

### Denials, explain, telemetry

* `%Warden.Denial{}` gains `reason` (the failing check's reason; a list in rule order for
  `any_of`) and `trace` (`[{rule, :ok | {:deny, reason}}]`, rule terms only, never
  values). Inspect shows `reason`, not `trace` args.
* `Warden.explain(actor_or_context, rule, opts) :: %Warden.Explanation{result, steps}`
  evaluates without short-circuiting. Its `result` always equals `authorize/3`.
* Telemetry `[:warden, :decision]`, measurements `%{count: n}`, metadata
  `%{layer, kind, rule, result, reason, actor_kind, tenant}`. `layer` is `:core`,
  `:plug`, `:absinthe`, `:ecto`, `:fields` or `:channel`. No subject, no value, ever.
  One event per decision call (a list counts as one event with `count`), so lists stay
  cheap.
* `deny/1` receives `reason`. The default handler ignores it unless
  `expose_denial_reasons: true`, then it adds `reason` (atoms only; the map of a
  `{atom, map}` reason is never exposed) next to the missing roles.

### Absinthe additions

* `authorize rule, on_deny: :null | {:replace, value} | :error` on a field: the denial
  result for that field only. Default `:error` (0.1 behaviour: through `deny/1`). `:null`
  on a non-null field fails compilation.
* `covered()` (above). Under `strict_mode: :all`, a field with `covered()` counts as
  declared.
* `can/2` as object, field and argument rules; `can/3` with `arg:` as field and argument
  rules only. Object rules with `can/2` over a list are batched per policy and tenant (one
  query per list for Ecto policies).
* Object rules (of objects, interfaces and unions, and `default_object_rule`) cannot read
  field arguments: `tenant_role(r, tenant: {:arg, path})` and `can(policy, action,
  arg: path)` in one fail compilation. An object rule decides a value wherever it is
  returned, and the arguments of the field that returned it are the client's choice.
* `redact_with Policy.Fields` on an object type (below). An object type linked to a
  struct (through a `can/2` policy's `for:` or `warden_schema`) whose field policy in the
  authorizer's `fields:` redacts a field the type exposes under the same identifier must
  declare `redact_with` for that field policy, else compilation fails. A type that
  exposes none of the redacted fields needs nothing.
* Verifier option `require_can_for: [Schema, ...]` (with `strict_mode: :all`): an object
  type whose rule does not use `can/2` for those schemas' policies fails compilation. The
  link from object type to schema is the policy's `schema:` and an explicit
  `warden_schema Schema` notation on the object.

### Policies (core) and `Warden.Ecto`

`Warden.Policy` is the core behaviour (no Ecto needed), so REST-only apps can use
`can/2` with in-memory policies:

    use Warden.Policy, authorizer: MyApp.Authz, for: MyApp.Doc, actions: [:read, :write]
    @callback allowed?(action, Actor.t(), value, context) :: boolean | {:deny, reason}
    @callback allowed_many(action, Actor.t(), [value], context) :: [boolean | {:deny, reason}]  # optional

`Warden.Ecto.Policy` builds on it (`schema:`, `as:`, `tenant:`, `actions:`) and adds, per
action, either a hand-written `scope(action, actor, tenant_id, context)` (an Ecto
`dynamic` over the `as:` binding, `true` or `false`; anything else raises) or
declarative clauses. Never both for one action (compile error). `allow` clauses are
ORed, `require` clauses are ANDed:

| Clause | Means |
|---|---|
| `rule: r` | a Warden rule over the actor only (no row) |
| `where: [col: value]` | column equals a literal (`nil` means `IS NULL`) |
| `through: assoc` / `{assoc, action}` | the `belongs_to` parent is allowed under its own policy (default: same action), same tenant |
| `through_any: assoc` / `{assoc, action}` | at least one row of a `has_many` or `many_to_many` assoc is allowed |
| `none: assoc` | the assoc has no rows |
| `actor_in: [cols]` | one of the columns equals the actor's subject id |
| `member_of: {schema, row_key, actor_key}` | a row in `schema` links this row to the actor |
| `grant: {schema, row_key, grantee_key, opts}` | an explicit share row, with optional `expires_at` |
| `through_type: {type_col, id_col, %{type => policy}}` | polymorphic parent; a type not in the map denies |
| `within: {bounds_key, col}` | the column is in the actor's `bounds[bounds_key]` |
| `when: fun/3` | escape hatch; returns a dynamic, like `scope/4` |
| `if_nil: :deny \| :tenant` (on `through:`) | a `nil` foreign key; default `:deny` |

A `through` chain that loops fails compilation, and so do an unknown association and a
`through` to a schema without a policy. When `allowed?/4` is not hand-written, single checks run one `EXISTS` query; the
clause compiler also derives an in-memory predicate where it can (preloaded parents),
and falls back to a query when it cannot.

Functions (all take an actor or a context map, plus `authorizer:` like the core API):
`Warden.Ecto.scope/3,4`, `allowed?/3,4`, `authorize/3,4`, `filter/3,4` (one query,
order kept), `allowed?` on `{schema, id}`, `to_sql/4`, `dataloader_query/2`,
`update_all/4` and `delete_all/3` (refuse a query that was not scoped for a write
action), `allowed_actors/3`, `explain/3`. Several tenants: `scope/3` without `tenant:` uses
`tenants/2` and ORs `(tenant = t AND dynamic_t)`; a tenant the actor is not in adds
nothing; a `NULL` tenant column is never visible unless the policy opts in. `through:`
across tenants is never allowed. Policy callbacks run at most once per actor, tenant and
action per call.

Tests that need a database are tagged `:postgres`, excluded by default, and run with
`mix test --only postgres` against `WARDEN_DATABASE_URL` (default
`postgres://localhost/warden_test`, created and dropped by the suite). CI adds a
Postgres service and runs that suite.

### Field policies

    use Warden.Fields, authorizer: MyApp.Authz, for: MyApp.Comment
    redact :body, with: "", unless: check(:live)

`Warden.redact/2,3` (struct, list, `deep: true` for nested registered structs),
`Warden.visible_fields/2`. `unless:` is any rule over the struct (value = the struct).
Compile time: every redacted field exists on the struct. In Absinthe, `redact_with`
replaces the object value after its object rule passes and before any child field
resolves, so default and custom resolvers see the redacted struct, on every subscription
publish too. `with: nil` on a field whose GraphQL type is non-null fails compilation.
Redaction never changes stored data, and inspect of anything Warden builds while
redacting never shows the redacted values.

### Phoenix channels

`use Warden.Phoenix.Channel, rule: r, value: fun, recheck: [:every_push, {:every, ms}]`
and `Warden.Phoenix.Channel.authorize_join/3`. The actor is built from the socket's
assigns (authorizer callback `socket_context/1`, default `socket.assigns`) on every
check. A denial stops the channel with a reason the client can show, and drops the push
in flight; nothing is pushed after access ends.

### Policy matrix

`use Warden.Test.Matrix, authorizer:, repo:, snapshot:` with `actor` and `resource`
fixtures; asserts that `Warden.Ecto.allowed?/3`, membership in `scope/4` and a
hand-written `allowed?/4` agree for every cell, records results and visible fields, and
compares with a readable snapshot that holds fixture names only. A policy without a
resource fixture fails. `Warden.Test.assert_policy_consistent/3`,
`Warden.Test.Absinthe.assert_matrix_matches/2`, `mix warden.matrix [--update]`.

### Implementation notes: v0.2 core

Paths are relative to `lib/warden/`.

- **One evaluator.** `evaluator.ex` evaluates rules for every layer: `one/3` (a value),
  `many/3` (a list) and `explain/3`. It threads the actor through the evaluation, so
  tenant roles read by one leaf are cached for the next, and returns the updated actor.
  `Warden.Rule.evaluate/3` keeps its 0.1 result shape; the failure map gains `reason` and
  `trace`.
- **Delegation is ANDed at the top.** A delegated actor's rule is evaluated for the actor
  and then (only when it passed) for the delegator; the decision is the AND of the two
  whole-rule decisions, never of single leaves, so `any_of` cannot be split between them.
  Over a list the delegator is asked only about the values the actor passed. Delegation
  is one level deep: an actor that already acts on behalf of another can neither delegate
  nor be delegated to (`ArgumentError`).
- **System actors** have a credential with `method: :system` and no scopes, which carries
  the `tenant:` binding and the `reason:`. So `session()` and `credential_scope/1` deny
  them too, and the binding code is the same as for bound credentials. An anonymous
  actor also fails `session()` and `credential_scope/1`. An unbound system actor has no
  tenants (`Warden.Actor.tenants/2`).
- **Checks.** A batched check's single value goes to `check_many/2` as a one-element list,
  or to `check/2` with `single: true`, so a catch-all `check/2` clause never answers a
  batched check by accident. `timeout:` runs the call in a process started with
  `spawn_monitor/1` that gets a copy of the caller's process dictionary (except keys that
  are atoms starting with `$`) and `$callers`; on timeout it is killed, Warden waits for
  its `:DOWN`, then flushes any reply it sent, so none arrives late. A raise inside `check_many/2` (with or without a timeout) becomes a
  `Warden.PolicyError`; a raise inside `check/2` propagates as in 0.1.
- **Batching.** `Evaluator.many/3` first decides every batched leaf (checks with
  `batch: true`, and `can/2` without `arg:`) for all values at once, then evaluates the
  rule per value with those results, short-circuiting over the other leaves.
- **Policy entry points.** `can/2,3` dispatches to any module that exports:
  - `__warden_policy__(:info)` returning `%{authorizer: module, for: module,
    actions: [atom], tenant: atom | nil, system_kinds: [atom],
    enforces_binding: boolean}`;
  - `__warden_decide__(action, actor, values, context)` returning one
    `true | false | {:deny, reason}` per value, in order.

  `use Warden.Policy` generates both (`__warden_decide__/4` is overridable and calls
  `allowed_many/4` or `allowed?/4`); `Warden.Ecto.Policy` implements them too.
  `Warden.Policy.Dispatch` (`policy/dispatch.ex`) screens every value before calling
  `__warden_decide__/4`: `nil` values, system actors of kinds not in `system_kinds`, and,
  for a bound actor, values whose tenant is another one or unknown (`{schema, id}` from
  `arg:` included) are denied without a call. A policy that applies the binding itself
  (a query scope with the bound tenant) sets `enforces_binding: true` and then also gets
  values of unknown tenant. Dispatch then checks the answer: a raise, a non-list, a wrong
  length or a bad element is a `Warden.PolicyError`. The policy is resolved from the rule
  term at runtime; the authorizer only names its policies in `policies:`, so it never
  depends on them at compile time, while `use Warden.Policy` checks at compile time that
  its authorizer lists it. `Warden.Policy.policy_for/2` finds the policy of a struct
  through that list, and the default `tenant_of/1` uses its `tenant:` field.
- **`can(..., arg: path)`** asks about `{for_module, id}` for the id at the path, or for
  every id of a list there. A missing id, an empty list, a list with a `nil` id or a
  `nil` value denies without asking the policy.
- **The binding screen.** Before any leaf but `public()` and `covered()`, the evaluator
  compares the tenant of the value (`tenant_of/1`, a scalar; a list, map or tuple counts
  as unknown) with the actor's bound tenant, once per value, and denies with
  `:tenant_binding` when both are known and differ. The batched pre-pass applies the
  same screen, so batch callbacks only see values the per-value path could reach. The
  policy dispatch keeps its own screen for values of unknown tenant (`{schema, id}`).
  A tenant from `{:arg, path}` that is not a scalar denies without `tenant_roles/3`.
- **Error messages describe, never print.** A `Warden.PolicyError` (or `ArgumentError`)
  about a check or policy answer, a handler result, a context or a guarded value names
  only its shape (`Warden.Shape`: type, struct name, size). A raise inside a batch or a
  policy is named by its exception module only, since exception messages can print the
  data they failed on.
- **GraphQL post middleware in two passes.** `absinthe/decide.ex` collects the values of
  a field in walk order, groups them by the rule that applies (abstract rule first, then
  the concrete type's rule for the values that passed), decides each group with
  `Evaluator.many/3` and wraps every value with its outcome; the 0.1 walk
  (`absinthe/middleware.ex`) then applies list policies, item errors and folds from those
  outcomes. Both passes are linear (`test/adversarial/batching_test.exs`).
- **Admitted values.** The pre middleware decides the parent object rule again for every
  field (defense in depth). For a value that this execution's post middleware admitted, it
  does not: that would turn one batched call per list into one call per value and field.
  Admitted are values whose (concrete, for abstract types) object rule is batched, and
  values replaced by `redact_with` (their rule was decided on the value before redaction,
  and deciding it again on the redacted struct could disagree). Only the pre specs of types
  that can be admitted carry `admissible: true` from the plan; every other field does no
  lookup at all.

  An admission is keyed by the concrete type and the response path of the value, so a
  lookup costs O(path depth), whatever the size of the value. The post walk records it at
  the value's OUTPUT position: admissions travel with item errors through the walk, after
  `:filter` removed items and with nested list indexes, and a position that becomes null
  (a bubble, a fold) drops them. This is sound because a child field's source at path P is
  exactly the value the parent's post walk left at P: Warden's post entry runs last (it
  moves itself behind middleware appended at runtime, so a value replaced after the
  resolver is decided as replaced), every field that can return the type carries a post
  entry, and a denied value is never left at a position (it is null or removed), so a path
  admitted for one value can never name another. Two documents run by
  `Absinthe.Pipeline.BatchResolver` share the accumulator (a 0.1 limit: they share the
  actor and the context too), but a value at a path in either document was decided by
  that document's own post walk before its fields ran. Absinthe resolving a different
  concrete type for the child than the walk decided simply misses the key and decides
  again. `test/adversarial/admission_paths_test.exs` covers `:filter`, nested lists and a
  value replaced after the resolver.
- **Cross-parent batching** (`batch_across_parents: true`) applies to object rules with
  batched leaves on fields that return one object (not a list, not an abstract type)
  inside a list. The post middleware hands the check to `Absinthe.Middleware.Batch` with a
  reference and resumes in `post_decided/2`. The actor and the context are encoded once per
  document execution into one binary kept in `resolution.acc` with a reference: Absinthe
  runs the batch function in another process, and a message would otherwise copy the
  context once per deferred check. The batch function groups the deferred checks by that
  reference (one execution, one actor and context), decodes once per group and decides
  each group with one `Evaluator.many/3` call, so the cost per check does not depend on
  the size of the context. The batch gets `timeout:` the longest check timeout of the
  rule plus 1 s (at least Absinthe's 5 s), so a slow check denies with `:unavailable`
  instead of exiting the document. Such checks have no `resolution`, and tenant roles read there
  are not written back to `resolution.acc`. The verifier fails compilation when the
  schema's `plugins/0` has no `Absinthe.Middleware.Batch`.
- **Field policies** (`fields.ex`, `fields/redactor.ex`). `use Warden.Fields` validates
  at expansion time (the struct is compiled, every field exists and is named once, the
  rule passes the core API's validation) and generates `__warden_fields__(:info)`
  returning `%{authorizer, for, struct_fields, redactions: [%{field, with, rule}]}`. The
  authorizer names its field policies in `fields:` without depending on them, like
  `policies:`; the registry `%{struct => fields_module}` is built per call from that
  list and refuses two policies for one struct. A redaction rule may not read field
  arguments (`{:arg, path}` tenants, `can(..., arg:)`) or use `covered()`: it is about
  the struct, and its checks get only the actor, the value and the context.
- **Redaction.** The structs of one policy are decided together, one
  `Evaluator.many/3` per distinct rule, with the actor threaded through. `deep: true`
  works level by level: the outermost registered structs of every term (walking maps,
  lists, improper lists and tuples; never into unregistered structs) are redacted as
  one batch per policy, then their redacted fields are the next level. Telemetry: one
  event per rule and group, `layer: :fields`, `kind: :field`.
- **`redact_with`** is `:warden_redact_with` meta on an object type. The plan adds
  `redactors: %{object_type => fields_module}` to a post spec (only when non-empty, so
  specs without redaction are unchanged): the return type's own for an object type,
  every object type's for an abstract type, and a field whose return type has a
  redactor but no object rule gets a post spec for it. `Decide` redacts the values that
  passed after deciding object rules, grouped by policy; for abstract types the
  concrete type is resolved once and reused, and a value whose concrete type cannot be
  determined is denied when a redactor may apply. A value that is not the policy's
  struct raises `Warden.PolicyError` (fail closed, without inspecting the value).
  Cross-parent batching passes the redactor in the batch key and redacts the passing
  values of a group together. Compile-time: the module is a field policy of the schema's
  authorizer; when the object's own rule names `can/2` policies or the object has a
  `:warden_schema` meta, the policy's struct must be one of them; `with: nil` on a
  same-named non-null field fails.
- **`on_deny:`** is stored as `:warden_on_deny` meta and copied into the field's pre spec.
  It decides only denials of the field rule (`kind: :field`); argument and object denials
  still go through `deny/1`.
- **`covered()`** is dropped from the plan like `public()`; `Plan` rejects it anywhere but
  as the whole rule of a field of an object type or interface with an object rule. The
  core API and `Warden.Plug` refuse it.
- **Telemetry.** The core API and `Warden.Plug` emit one event per call; the Absinthe pre
  middleware one per field resolution (`kind` of the denial, or `:field` with the list of
  rules it ran), the post middleware one per field with values (`kind: :object`, `count`
  = values decided), a subscribe-time check one with `kind: :subscribe`. `tenant` is the
  first tenant a `tenant_role` rule resolved, else the actor's bound tenant.
- **`default_actor_key/1`** keeps the 0.1 term for a plain user or anonymous actor and
  adds the kind, `system?`, the credential (method, sorted scopes, tenant, bounds), the
  actor's bounds and the delegator's key otherwise. Bounds are included because policies
  read them: two actors with different bounds must not share a subscription payload.

### Implementation notes: `Warden.Ecto`

Paths are relative to `lib/warden/`.

- **Layout.** `ecto/policy.ex` (the `use` macro, `allow` and `requires`),
  `ecto/policy/compiler.ex` (compile-time validation and the per-action plan),
  `ecto/policy/graph.ex` (checks across policies), `ecto/scope.ex` (dynamics),
  `ecto/memory.ex` (in-memory decisions), `ecto/decide.ex` (`__warden_decide__/4`),
  `ecto/audience.ex`, `ecto/explain.ex` and `ecto.ex` (the public functions). All of it
  compiles only when `Ecto` is loaded; `to_sql/4` only when `Ecto.Adapters.SQL` is.
- **`requires`, not `require`.** `require` is an Elixir special form and cannot be
  imported as a macro, so the ANDed clause is `requires action, clauses`.
- **Every `allow` names the actor.** An `allow` clause needs a key about the actor
  (all but `where:`, `none:`, `if_nil:`), else compilation fails: a clause about rows
  alone would admit every actor, anonymous ones included. `rule: public()` says it on
  purpose.
- **Gates before the policy** (`Scope.gate/4`): a system actor of a kind not in
  `system_kinds:`, a `NULL` tenant without `null_tenant: true`, a tenant other than the
  bound one (an untenanted row has no tenant, so a bound actor gets none), and a tenant
  that is not in `Warden.Actor.tenants/2`. The last gate makes single checks, filters
  and scopes over every tenant give the same answer for a clause that does not check
  membership itself; as a consequence an anonymous actor (no tenants) sees no rows of a
  tenanted schema.
- **System actors** pass only `allow` clauses whose `rule:` contains `kind/1` with their
  kind (goal 9); `requires` clauses apply to everyone.
- **Delegation.** `Warden.Ecto` ANDs both sides itself (scopes, `allowed_actors`,
  `explain`), over the tenants both actors are in. `__warden_decide__/4` decides the
  actor it is given as one side, because the evaluator already asks the delegator
  separately and ANDs the results.
- **Once per call.** One `Scope` state per call memoizes the verdict per policy, action,
  tenant and actor, each `rule:` part, and `tenants/2`, so callbacks and checks run at
  most once per actor, tenant and action, and a `through` parent's dynamic is reused.
- **Errors across policies.** A policy only names other policies at runtime (through
  the authorizer's `policies:`), so a `through` target without a policy, a cycle over
  several policies, a parent of another authorizer or without the action, and mixed
  tenancy are found by `Graph.validate/1`: from `@after_verify` as compiler warnings,
  and on first use as `Warden.PolicyError` (a valid result is cached in
  `:persistent_term`). A `through` to the schema itself is known in the module and fails
  compilation.
- **In memory.** `Memory` returns `true`, `false` or `:unknown` with three-valued AND
  and OR; unknown structs go to one query per tenant and query prefix
  (`__meta__.prefix`, also in `allowed_actors`, `explain` and batched `can/2`).
  `through_any:` over a `has_many` is only trusted when a loaded child whose foreign key
  points at the row is allowed; over a `many_to_many`, and `none:`, never, because a
  preload may be filtered or assembled by hand. `within:` drops `nil` from the bounds,
  so a `NULL` column never matches.
  An association with a `where:` or `join_where:` filter fails compilation in
  `through:`, `through_any:` and `none:`: the subquery would leave the filter out.
- **`grant:` expiry** compares with the current time as a parameter of the
  `expires_at` field's type, not the database's `now()`, so session time zones do not
  matter. That needs the type, so `grant:` with `expires_at:` through a table name
  fails compilation.
- **Guarded writes.** `scope/4` marks the `where` it adds (its `file` field holds
  `warden:scope:<policy>:<action>`). `update_all/4` and `delete_all/3` accept a query
  only with a mark for one of the policy's `write_actions:` on its root schema, no
  `or_where` after it, and no combinations; `update_all/4` also refuses `set`, `inc`,
  `push` and `pull` on the tenant field and on the `through:` and `through_type:`
  fields of the write action's clauses. Other fields are checked before the write only.
- **Query guards** (`ecto/guard.ex`). `scope/4` raises for combinations (each arm needs
  its own scope) and preloads (scoped preloads instead), and both `scope/4` and the
  write guard raise for a CTE named like the root's table or any table in the subqueries
  of a Warden-marked `where`, since Postgres resolves an unqualified name to the CTE.
  `dataloader_query/2` raises for a subquery or fragment root and for a bare table name
  a policy covers. Error messages describe a bad value's shape (`Info.shape/1`), never
  the value.
- **Telemetry.** `scope/4` (and `to_sql/4`, `dataloader_query/2`) emit `kind: :scope`,
  denied when the scope is `false`; `allowed?`, `authorize` and `filter` go through the
  core decision code with `layer: :ecto`; `allowed_actors/4` emits one event per actor
  (each is a decision about a different actor). `explain/4`, `update_all/4` and
  `delete_all/3` emit none, like `Warden.explain/3`.
- **`repo:`.** The policy option names the repo for the queries Warden runs itself; the
  design's option list did not have one, but a `can/2` decision inside GraphQL has no
  other way to reach a repo.

### Implementation notes: policy matrix

- **Layout.** `test.ex` (`assert_policy_consistent/4`, core), `test/cells.ex` (names and
  messages), `test/matrix.ex` (needs `ecto`), `test/matrix/snapshot.ex` (render, parse,
  diff), `test/absinthe.ex` (needs `absinthe`) and `lib/mix/tasks/warden.matrix.ex`.
- **ExUnit only when called.** Failures raise `ExUnit.AssertionError`; nothing references
  ExUnit at load time, and the `:no_optional_deps` suite checks that neither the module
  nor the application is loaded after Warden runs. `Warden.Test.Matrix` uses
  `ExUnit.Case` only in the test modules that `use` it.
- **Ordering.** `use Warden.Test.Matrix` registers its `@before_compile` before
  `use ExUnit.Case`, so the generated setup (fixtures, after the module's own `setup`
  blocks) and test exist when ExUnit collects them; the sandbox checkout is a setup
  registered before the module's own.
- **Snapshot comparison** parses both files into cells and compares those, so a change
  in column widths is not a difference. `run!/2` takes the mode from `WARDEN_MATRIX`
  (`print`, `update`), which `mix warden.matrix` sets when it runs
  `mix test --only warden_matrix` in a child process.
- **Redacted fields** are the fields whose value `Warden.redact/3` changes, recorded
  only where the actor may take an action on the resource.
