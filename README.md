# absinthe_warden

Role- and permission-based authorization for [Absinthe](https://github.com/absinthe-graphql/absinthe)
GraphQL schemas.

Rules attach to fields, object types, interfaces, unions, arguments and input fields.
Denied data becomes `null` (folded to the nearest nullable parent); the rest of the
request still resolves. Queries, mutations and subscriptions are enforced the same way.

- Warden attaches its middleware at schema compile time, after your `middleware/3`, so
  your own middleware cannot remove it. A compile-time verifier checks every field.
- Only a literal `true` from a check grants access. Anything else that is not `false`
  raises `Warden.PolicyError`.
- Field and argument rules run before the resolver, so a denied mutation never runs.
- A denied object is `null` as a whole, so `__typename` does not reveal it.
- Subscription payloads resolve as each subscriber, re-checked on every publish.
- The default error says only `"Forbidden"` with `extensions.code = "FORBIDDEN"`.
- Rules that name an unknown role, permission or check fail compilation.

Supports Absinthe `>= 1.7.0`; developed against 1.12. See
[`docs/DESIGN.md`](docs/DESIGN.md) for the design and the implementation notes.

Absinthe 1.7.10 has two published high-severity advisories (EEF-CVE-2026-43967, a
quadratic fragment-name check, and EEF-CVE-2026-42793, atom table exhaustion). Both are
in Absinthe, not Warden, and Warden cannot mitigate them. Upgrade Absinthe if you can.

absinthe_warden is a community library. It is not affiliated with the absinthe-graphql
project.

## Installation

```elixir
def deps do
  [
    {:absinthe_warden, "~> 0.1"}
  ]
end
```

## The authorizer

The authorizer declares your catalogs and tells Warden who the actor is.

```elixir
defmodule MyApp.Authz do
  use Warden.Authorizer,
    roles: [:admin, :editor, :viewer],
    permissions: ["posts:read", "posts:write"],
    role_hierarchy: %{admin: [:editor], editor: [:viewer]},
    role_permissions: %{admin: :all, editor: ["posts:write"], viewer: ["posts:read"]},
    checks: [:self, :owner]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: user.roles

  # Optional, default [].
  @impl true
  def permissions(user, _context), do: user.extra_permissions

  # Required when `checks:` is not empty.
  @impl true
  def check(:self, %Warden.Check{actor: actor, value: user}), do: user.id == actor.subject.id
  def check(:owner, %Warden.Check{actor: actor, value: post}), do: post.author_id == actor.subject.id
end
```

| Option | Meaning |
|---|---|
| `roles` | Role catalog (required). |
| `permissions` | Permission catalog. `nil` (default) accepts any term. |
| `role_hierarchy` | `%{role => [implied roles]}`. Validated: catalog roles only, no cycles. |
| `role_permissions` | `%{role => [permissions] \| :all}`. `:all` grants every permission. |
| `checks` | Names handled by `check/2`. |
| `expose_denial_reasons` | Add missing roles and permissions to the default error. Default `false`. |
| `spec_compliant_errors` | Set to `true` if you run Absinthe with `spec_compliant_errors: true`. |

The actor (`%Warden.Actor{subject, roles, permissions}`) is built once per execution:
roles are expanded through the hierarchy, `role_permissions` are merged with
`permissions/2`. `roles/2` and `permissions/2` must return lists. Roles and permissions
outside the catalog are dropped and logged, never granted. A `nil` subject is anonymous:
no roles, no permissions, and `roles/2` is not called.

Optional callbacks: `deny/1` (see [Denial handling](#denial-handling)) and
`actor_key/1` (see [Subscriptions](#subscriptions)).

## Declaring rules

```elixir
defmodule MyApp.Schema do
  use Absinthe.Schema
  use Warden.Schema, authorizer: MyApp.Authz

  object :user do
    authorize any_of([role(:admin), check(:self)])     # object rule

    field :name, :string                               # no rule
    field :email, :string do
      authorize any_of([role(:admin), check(:self)])   # field rule
    end
  end

  input_object :post_filter do
    field :include_drafts, :boolean, default_value: false do
      authorize role(:editor)                          # input-field rule
    end
  end

  query do
    field :users, list_of(non_null(:user)) do
      authorize authenticated()
      arg :include_deleted, :boolean, default_value: false
      authorize_args include_deleted: role(:admin)     # argument rule
      resolve &Users.list/2
    end
  end
end
```

`use Warden.Schema` must come after `use Absinthe.Schema`. In type modules pulled in with
`import_types`, add `use Warden.Notation` after `use Absinthe.Schema.Notation`.

### Rules

| Builder | Passes when |
|---|---|
| `public()` | always |
| `authenticated()` | the actor has a subject |
| `role(r)` | the actor has role `r` (after hierarchy expansion) |
| `any_role(rs)` | the actor has at least one of `rs` |
| `permission(p)` | the actor has permission `p` |
| `all_permissions(ps)` / `any_permission(ps)` | all / at least one of `ps` |
| `check(name)` / `check(name, opts)` | `check/2` returns `true` |
| `all_of(rules)` / `any_of(rules)` | all / at least one rule passes |
| `deny()` | never |

There is no negation on purpose. Rules are plain terms evaluated at compile time; build
them from literals, module attributes or compile-time expressions.

### Where rules apply

- **Field rule** (`authorize` in an object field): runs before the resolver. The
  `check/2` value is the parent object.
- **Interface field rule**: merged (AND) into the same-named field of every object that
  implements the interface, because GraphQL resolves the concrete object's field.
- **Object rule** (`authorize` in `object`, `interface` or `union`): applied to every
  value of that type after it resolves, including list items, values behind interfaces
  and unions, and values from Dataloader, `async` and `batch`. An interface's object rule
  also applies to its implementors when they are returned directly. A union's rule
  applies to values returned through the union. Object rules on the root types apply to
  every root field.
- **Argument rule** (`authorize_args`): applies when the argument value, after variables
  and defaults, differs from the schema default. An explicit `null` for an argument with
  a non-null default counts as different.
- **Input-field rule** (`authorize` in an `input_object` field): same rule as arguments,
  checked through nested input objects and lists of input objects.

### SDL schemas

Use `Warden.Hydrate.meta/2` in `hydrate/2`:

```elixir
def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :email}, [%{identifier: :user} | _]) do
  [Warden.Hydrate.meta(rule: role(:admin))]
end
```

Absinthe's `{:meta, ...}` hydration replaces the node's meta; pass your other meta as
the second argument: `Warden.Hydrate.meta([rule: role(:admin)], cache: false)`.

## Schema options

| Option | Default | Meaning |
|---|---|---|
| `authorizer` | required | Your `Warden.Authorizer` module. |
| `strict_mode` | `false` | `false`, `:root` or `:all`; see below. |
| `default_object_rule` | `nil` | Rule for object types without their own rule (root and introspection types excluded). |
| `introspection` | `public()` | Rule that guards `__schema` and `__type`. `__typename` is never guarded. |
| `list_policy` | `:null_item` | Default list policy. |

`default_object_rule: public()` does nothing except hide that a type has no rule. Do not
use it to silence strict mode.

### `strict_mode`

Rules are optional by default: a field or type without a rule is allowed.

| Value | Compile-time requirement |
|---|---|
| `false` | none |
| `:root` | every field of the query, mutation and subscription types declares a rule (`public()` counts) |
| `:all` | every field of every object type declares a rule (an interface field rule counts); introspection excluded |

A missing rule is a `CompileError` that names every offending field.

## Denial handling

On a denial Warden calls `deny/1` on your authorizer with a `%Warden.Denial{}`:
`kind` (`:field | :object | :argument | :subscribe | :introspection`), `rule`,
`failed_rule`, `missing_roles`, `missing_permissions`, `actor`, `path`, `field`,
`parent_type`, `type`, `value_index`, `argument` and `list_policy`.

| Return | Effect |
|---|---|
| `{:error, term}` | the field becomes `null` with this error (string, map or keyword list) |
| `:null` | the field becomes `null` with no error |
| `{:replace, value}` | the field resolves to `value` (`kind: :field` only); object rules still apply to it |

The default returns `{:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}`,
and `:null` for items removed by the `:filter` policy. Any other return raises
`Warden.PolicyError`.

A `null` in a non-null position folds to the nearest nullable parent, as the GraphQL
spec requires. For `:null` on a non-null field, Absinthe adds its own
"Cannot return null for non-nullable field" error.

When a field is denied, the rest of its middleware does not run either.

## List policies

Set per field with `list_policy :filter` (or the schema-wide `list_policy:` option):

| Policy | Denied item | Item type non-null |
|---|---|---|
| `:null_item` (default) | becomes `null`, the error points at the item index | folds to the list field |
| `:filter` | removed, no error | removed |
| `:fail_list` | the whole list field is denied | same |

With `:filter`, a handler that returns `{:error, term}` keeps the item as `null` with
that error, because Absinthe cannot report an error for an item that is not in the list.
With nested lists whose innermost items are non-null (`[[T!]]`), Absinthe nulls the whole
field when any inner list becomes `null`; Warden keeps every item error on the field.

## Subscriptions

- **Subscribe time.** Warden wraps every subscription field's `config`. The subscription
  root type rule, the field rule and the argument rules run before your `config`; a
  denial refuses the subscription with the denial error.
- **Publish time.** Every published event resolves with the subscriber's context; the
  actor is rebuilt for every event and all rules run again.
- **`context_id`.** Absinthe resolves an event once per `context_id` and document and
  sends the result to every subscriber that shares them. When your `config` sets
  `context_id`, Warden appends `actor_key(actor)`, so subscribers with different access
  never share a payload. The default key hashes the subject's `:id` (or the whole
  subject), the roles and the permissions. If your checks read other subject attributes,
  override `actor_key/1` to include them.

The context of a subscription is the context at subscribe time. A revoked role or
permission applies on the next event only if `roles/2` and `permissions/2` read current
data, not a user struct stored in the context.

## Security model and limits

Warden enforces rules on what GraphQL execution returns and on what reaches resolvers.
It does not protect against the following:

- **Object rules on a mutation's return type do not stop the mutation.** They null the
  returned object after the resolver has run. Put a field rule on the mutation field to
  stop it.
- **The actor is cached per execution.** It is built from the context on the first
  Warden check of a request. Later changes to the context (by a resolver or middleware)
  do not change it; changes made before the first check do.
- **Resolvers and middleware that change the context mid-execution** are trusted code.
  If they change what `subject/1`, `roles/2` or `checks` see before the actor is built,
  Warden uses those values.
- **Middleware that rewrites `resolution.middleware` at runtime** to remove entries can
  remove Warden's post check. Middleware appended at runtime is handled (the check moves
  behind it); removal is not.
- **Data inside scalars** (for example a JSON scalar that returns a restricted map) is
  not checked; Warden checks object types.
- **Type confusion in resolvers.** A resolver that returns a value of another type is
  checked against the field's declared type.
- **Non-deterministic `resolve_type`.** Warden calls your `resolve_type` for every value
  behind an interface or union; if it can give a different answer to Absinthe's own call,
  the concrete type's rule may not match what is rendered.
- **Existence of list items.** With `:null_item`, the response shows that an item exists
  at an index. Use `:filter` to hide it.
- **Introspection output** is not filtered. Use the `introspection:` option to restrict
  `__schema` and `__type` as a whole.
- **Batched subscription publishing.** A custom Pubsub `run_docset/3` that runs documents
  through `Absinthe.Pipeline.BatchResolver` shares `acc` and merges contexts across
  subscribers; per-subscriber identity cannot hold there. Absinthe's own publisher runs
  every document separately.
- **Non-goals for v1:** permission wildcards, rate limiting, `@defer`/`@stream`.

## Development

```sh
mise exec -- mix test
```

The property tests run 500 cases by default; set `WARDEN_PROPERTY_RUNS` for more.

To run the suite against Absinthe 1.7.10 (separate lockfile, deps and build dirs):

```sh
ABSINTHE_VERSION=1.7.10 MIX_LOCKFILE=mix.lock.absinthe17 \
  MIX_DEPS_PATH=deps_absinthe17 MIX_BUILD_ROOT=_build_absinthe17 \
  mise exec -- mix test
```
