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

Requires Absinthe `~> 1.12`. See
[`docs/DESIGN.md`](docs/DESIGN.md) for the design and the implementation notes.

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
outside the catalog are dropped and logged, never granted. A `nil` or `false` subject is
anonymous: no roles, no permissions, and `roles/2` is not called. A subject of `:error`
or `{:error, _}` (for example a failed token lookup) raises `Warden.PolicyError`: return
`nil` for "no user".

Optional callbacks: `deny/1` (see [Denial handling](#denial-handling)) and
`actor_key/2` (see [Subscriptions](#subscriptions)).

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
  Interface argument rules are merged the same way, over the union of the arguments the
  object field and every interface field declare.
- **Object rule** (`authorize` in `object`, `interface` or `union`): applied to every
  value of that type after it resolves, including list items, values behind interfaces
  and unions, and values from Dataloader, `async` and `batch`. An interface's object rule
  also applies to its implementors when they are returned directly. A union's rule
  applies to values returned through the union. Behind an interface or union, every
  object type's rule is in reach: if `resolve_type` returns a type outside the declared
  members, that type's rule still applies. Object rules on the root types apply to every
  root field, including the root's `__typename`, `__schema` and `__type`.
- **Argument rule** (`authorize_args`): applies when the client sends the argument
  (after variables and defaults) and either it has no default (any value, `null`
  included, applies) or the value differs from a declared default. When the object field
  and its interface fields declare the argument differently: if any declaration has no
  default, every present value is restricted (also one an interface default filled in);
  otherwise a value is restricted when it differs from any declared default. This is
  fail-closed on purpose: Warden cannot tell which declaration Absinthe used to fill in
  a default for a given selection (Absinthe swaps the interface field for the concrete
  field before execution, and merges same-named selections into one), so with an object
  default of `false` and no interface default, an omitted argument on the concrete type
  is still restricted.
- **Input-field rule** (`authorize` in an `input_object` field): same rule as arguments,
  checked through nested input objects and lists of input objects.

### SDL schemas

Use `Warden.Hydrate.meta/2` in `hydrate/2`:

```elixir
def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :email}, [%{identifier: :user} | _]) do
  [Warden.Hydrate.meta(rule: role(:admin))]
end
```

On an argument node (`InputValueDefinition` of a field), `rule:` is an argument rule.

Absinthe's `{:meta, ...}` hydration replaces the node's meta. Warden installs a hydrator
that keeps its own keys across a later `{:meta, ...}` and fails compilation when two
hydrations set a Warden key to different values. You can also pass your other meta as
the second argument: `Warden.Hydrate.meta([rule: role(:admin)], cache: false)`.

## Schema options

| Option | Default | Meaning |
|---|---|---|
| `authorizer` | required | Your `Warden.Authorizer` module. |
| `strict_mode` | `false` | `false`, `:root` or `:all`; see below. |
| `default_object_rule` | `nil` | Rule for object types without their own rule (root and introspection types excluded). |
| `introspection` | `public()` | Rule that guards `__schema` and `__type` on every object Absinthe adds them to (any type named `Query` or `RootQueryType`, not only the root). `__typename` is guarded only by root object rules. |
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

A missing rule is a `CompileError` that names every offending field. Introspection
fields are recognized by their GraphQL name (`__typename`, `__schema`, `__type`), so a
field whose identifier starts with `__` is an ordinary field.

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

The default handler:

- `kind: :object` (a denied object, list item or `:fail_list` list): `:null`, no error.
  A client cannot tell an object it may not see from one that does not exist.
- `:field`, `:argument`, `:subscribe` and `:introspection`:
  `{:error, %{message: "Forbidden", extensions: %{code: "FORBIDDEN"}}}`.
- Items removed by the `:filter` policy: `:null`.

Return an error for object denials from your own `deny/1` if you want them reported.
Any other return raises `Warden.PolicyError`.

A `null` in a non-null position folds to the nearest nullable parent, as the GraphQL
spec requires. For `:null` on a non-null field, Absinthe adds its own
"Cannot return null for non-nullable field" error. Absinthe does not fold a non-null
field of an object that sits two or more list levels deep (`[[T]]`); Warden folds those
itself when it nulled the field.

When a field is denied, the rest of its middleware does not run either.

## List policies

Set per field with `list_policy :filter` (or the schema-wide `list_policy:` option):

| Policy | Denied item | Item type non-null |
|---|---|---|
| `:null_item` (default) | becomes `null` (with an error at the item index if the handler returns one) | folds to the list field |
| `:filter` | removed, no error | removed |
| `:fail_list` | the whole list field is denied | same |

With `:filter`, a handler that returns `{:error, term}` keeps the item as `null` with
that error, because Absinthe cannot report an error for an item that is not in the list.
Error paths use the index in the returned list (filtered items do not count), so they
never point at another item or reveal the original position.
With nested lists whose innermost items are non-null (`[[T!]]`), Absinthe nulls the whole
field when any inner list becomes `null`; Warden keeps every item error on the field.

## Subscriptions

- **Subscribe time.** Warden wraps every subscription field's `config`. The subscription
  root type rule, the field rule and the argument rules run before your `config`; a
  denial refuses the subscription with the denial error. Object rules of the return type
  that do not use `check(...)` (so they do not depend on the payload) run too: when the
  return type's rule denies, or every possible concrete type's rule denies, the
  subscription is refused, because the subscriber could never see an event.
- **Publish time.** Every published event resolves with the subscriber's context; the
  actor is rebuilt for every event and all rules run again.
- **`context_id`: sharing is off by default.** Absinthe resolves an event once per
  `context_id` and document and sends the result to every subscriber that shares them.
  Warden removes any `context_id` your `config` sets, so every subscription resolves on
  its own, with its own actor.
- **Opt-in sharing.** Define `actor_key(actor, context)` in your authorizer. Warden then
  appends the key you return to the `context_id`; subscriptions with equal keys share one
  resolution. Return `nil` to not share a subscription. The key must cover everything
  your rules read: subject attributes, roles, permissions, and context values your
  checks use. `Warden.Authorizer.default_actor_key/1` (subject `:id`, roles, permissions)
  is a building block. Subscriptions that share a key share fate: they receive the same
  payload, so a revocation that only changes per-session data the key does not cover does
  not reach the subscriptions that share with it.

The context of a subscription is the context at subscribe time. A revoked role or
permission applies on the next event only if `roles/2` and `permissions/2` read current
data, not a user struct stored in the context.

## Security model and limits

Warden enforces rules on what GraphQL execution returns and on what reaches resolvers.
It does not protect against the following:

- **Object rules on a mutation's return type do not stop the mutation.** They null the
  returned object after the resolver has run. Put a field rule on the mutation field to
  stop it. Warden prints a compile-time warning for every mutation that has an object rule
  on its return type and no root, field or argument rule. Declare `authorize public()` on
  a mutation that anyone may run to state that and silence the warning.
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
- **Existence of list items.** With `:null_item`, the response shows that a position
  exists in the list (as `null`). Use `:filter` to hide it.
- **Introspection output** is not filtered. Use the `introspection:` option to restrict
  `__schema` and `__type` as a whole.
- **`Absinthe.Pipeline.BatchResolver` merges contexts.** It merges the context of every
  document in a batch into one (`deps/absinthe/lib/absinthe/pipeline/batch_resolver.ex:16`;
  the first document's keys win), so every document in a batch runs as the same user.
  That is Absinthe's behaviour, not Warden's; do not batch documents from different
  users.
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

Static checks (Dialyzer must report 0 warnings):

```sh
mise exec -- mix compile --warnings-as-errors --force
mise exec -- mix format --check-formatted
mise exec -- mix dialyzer
MIX_ENV=test mise exec -- mix dialyzer   # also covers test/support, like ElixirLS
```
