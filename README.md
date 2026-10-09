# warden

Role- and permission-based authorization for Elixir, with Absinthe and Plug
integrations. One authorizer module, two front ends:

- **REST and plain Elixir.** `Warden.authorize/3` and friends for any code, and
  `Warden.Plug` for Plug and Phoenix: route rules in the router or a controller, and
  resource checks (`value: post`) inside actions.
- **GraphQL.** `use Warden.Absinthe` in an Absinthe schema. Rules attach to fields,
  object types, interfaces, unions, arguments and input fields. Denied data becomes
  `null` (folded to the nearest nullable parent); the rest of the request still
  resolves. Queries, mutations and subscriptions are enforced the same way.

Common guarantees:

- Only a literal `true` from a check grants access. Anything else that is not `false`
  raises `Warden.PolicyError`.
- Rules that name an unknown role, permission or check fail: at compile time for
  schemas and plugs, at call time (with `Warden.PolicyError`) for the core API.
- The default denial says only "Forbidden". Revealing missing roles is opt-in.

GraphQL specifics:

- Warden attaches its middleware at schema compile time, after your `middleware/3`, so
  your own middleware cannot remove it. A compile-time verifier checks every field.
- Field and argument rules run before the resolver, so a denied mutation never runs.
- A denied object is `null` as a whole, so `__typename` does not reveal it.
- Subscription payloads resolve as each subscriber, re-checked on every publish.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the design and the implementation notes.

Warden is a community library. It is not affiliated with the absinthe-graphql or Plug
projects.

## Installation

```elixir
def deps do
  [
    {:warden, "~> 0.1"},
    # Optional, each enables its layer:
    {:absinthe, "~> 1.12"},  # Warden.Absinthe
    {:plug, "~> 1.14"}       # Warden.Plug
  ]
end
```

`absinthe` and `plug` are optional dependencies. The core (`Warden`, `Warden.Rule`,
`Warden.Authorizer` and the structs) works without either; `Warden.Absinthe` and
`Warden.Plug` are compiled only when their dependency is present.

## Choosing the authorizer

Configure a default, and pass `authorizer:` wherever you want a specific one. Both are
first-class:

```elixir
# config/config.exs: the default for every entry point
config :warden, authorizer: MyApp.Authz
```

| Entry point | Configured default | Explicit |
|---|---|---|
| GraphQL schema | `use Warden.Absinthe` | `use Warden.Absinthe, authorizer: MyApp.Authz` |
| Plug | `plug Warden.Plug, rule: role(:admin)` | `plug Warden.Plug, rule: role(:admin), authorizer: MyApp.Authz` |
| Controller | `Warden.Plug.authorize(conn, rule, value: post)` | `Warden.Plug.authorize(conn, rule, value: post, authorizer: MyApp.Authz)` |
| Core | `Warden.actor(context)`, `Warden.authorize(ctx, rule)` | `Warden.actor(context, authorizer: MyApp.Authz)`, `Warden.authorize(ctx, rule, authorizer: MyApp.Authz)` |

Resolution order, the same everywhere: the explicit `authorizer:` option, then the
authorizer of the `%Warden.Actor{}` you pass (an explicit option that names a different
module raises `Warden.PolicyError`), then the configured default. With none of them,
Warden raises an `ArgumentError` that names the config line; for a schema or a plug that
happens at compile time.

Several authorizers side by side (for example a separate admin API with its own role
catalog) are just explicit options:

```elixir
plug Warden.Plug, rule: role(:operator), authorizer: MyApp.AdminAuthz
Warden.authorize(context, role(:operator), authorizer: MyApp.AdminAuthz)
```

The default is read with `Application.compile_env/2`, because schemas and plugs resolve
it at compile time. Set it in `config/config.exs` (or a per-env file), not in
`config/runtime.exs`: a runtime value that differs from the compiled one makes the
release refuse to boot.

## The authorizer

The authorizer declares your catalogs and tells Warden who the actor is. The same module
serves GraphQL, Plug and the core API.

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

The actor (`%Warden.Actor{subject, roles, permissions, authorizer}`) is built once per
GraphQL execution, on every `Warden.Plug` check, and on every core call given a context
map (never for a core call given an actor): roles are expanded through the hierarchy, `role_permissions` are merged with
`permissions/2`. `roles/2` and `permissions/2` must return lists. Roles and permissions
outside the catalog are dropped and logged, never granted. A `nil` or `false` subject is
anonymous: no roles, no permissions, and `roles/2` is not called. A subject of `:error`
or `{:error, _}` (for example a failed token lookup) raises `Warden.PolicyError`: return
`nil` for "no user".

Optional callbacks:

- `deny/1` (GraphQL, see [Denial handling](#denial-handling)) and `actor_key/2` (GraphQL
  subscriptions, see [Subscriptions](#subscriptions));
- `conn_context/1` and `deny_conn/2` (Plug, see [Plug](#plug)).

## Core API

For controllers, contexts, jobs: any Elixir code.

```elixir
import Warden.Rule

ctx = %{current_user: user}

# Each call with the configured default, then with an explicit authorizer.
actor = Warden.actor(ctx)
actor = Warden.actor(ctx, authorizer: MyApp.Authz)

:ok = Warden.authorize(ctx, check(:owner), value: post)
:ok = Warden.authorize(ctx, check(:owner), value: post, authorizer: MyApp.Authz)
# a denial: {:error, %Warden.Denial{kind: :call}}

Warden.allowed?(ctx, role(:admin))                                   # true / false
Warden.allowed?(ctx, role(:admin), authorizer: MyApp.Authz)

Warden.authorize!(ctx, check(:owner), value: post)                   # :ok or raises Warden.ForbiddenError
Warden.authorize!(ctx, check(:owner), value: post, authorizer: MyApp.Authz)

Warden.filter(ctx, check(:owner), posts)                             # the posts the actor may see
Warden.filter(ctx, check(:owner), posts, authorizer: MyApp.Authz)

# An actor built once per request works wherever a context map does, and keeps the
# authorizer it was built with; an explicit `authorizer:` must name that same module:
Warden.allowed?(actor, role(:admin))
Warden.allowed?(actor, role(:admin), authorizer: MyApp.Authz)
```

- Options: `authorizer:` (resolution order above), `value:` (the resource, given to
  checks as `Warden.Check.value`), `context:` (given to checks as `Warden.Check.context`
  when you pass an actor).
- The rule is validated against the authorizer's catalog on every call. An unknown role,
  permission or check raises `Warden.PolicyError` rather than silently denying.
- An actor built by a different authorizer than the call resolves to raises
  `Warden.PolicyError`, and so does a hand-built `%Warden.Actor{}` without an
  authorizer.
- `Warden.ForbiddenError` carries the denial and `plug_status: 403`, so Phoenix renders it
  as a 403 without Warden depending on Plug. Its message is `"Forbidden"`, and names the
  missing roles and permissions only when the authorizer sets
  `expose_denial_reasons: true`.

## Plug

Needs the `plug` dependency.

```elixir
import Warden.Rule

plug Warden.Plug, rule: role(:admin)                            # configured default
plug Warden.Plug, rule: role(:admin), authorizer: MyApp.Authz   # explicit
plug Warden.Plug, rule: authenticated(), on_deny: {MyAppWeb.Auth, :deny}
plug Warden.Plug, rule: authenticated(), on_deny: {MyAppWeb.Auth, :deny}, authorizer: MyApp.Authz
```

- `init/1` resolves the authorizer and validates the rule against its catalog. Phoenix
  and `Plug.Builder` run `init/1` at compile time, so a typo in a role, permission or
  check fails compilation.
- There is no actor cache. Every check (`call/2`, `authorize/3`, `authorize!/3`) builds
  the actor from the current conn: the authorizer's `conn_context/1` (default
  `Map.put(conn.assigns, :conn, conn)`, so a `subject/1` that reads
  `context[:current_user]` serves GraphQL and REST alike), then `subject/1`, `roles/2`
  and `permissions/2`. A later plug that logs out, impersonates, drops privileges or
  switches the tenant is always seen. Keep these callbacks cheap: read from the assigns,
  and load the user and its roles in an earlier plug, not in the callbacks.
- `Warden.Plug.actor(conn)` / `Warden.Plug.actor(conn, authorizer: MyApp.Authz)` builds
  an actor now and stores nothing. Pass it to the core API to reuse it for several checks
  in one request; that deliberately freezes the roles for as long as you hold it.
- `on_deny: {module, function}` must name an existing `function/2` (checked by
  `init/1`, except for a module still being compiled, such as the controller itself).
- On denial: `on_deny: {module, function}`, else the authorizer's `deny_conn/2`, else the
  default, which sends `401 Unauthorized` to an anonymous actor and `403 Forbidden`
  otherwise. The plug always halts a denied conn, whatever the handler returns, and sends
  the default response if the handler sent none.

### In a Phoenix controller

```elixir
defmodule MyAppWeb.PostController do
  use MyAppWeb, :controller

  import Warden.Rule

  # Route-level rules, checked before any action runs: configured default, then explicit.
  plug Warden.Plug, [rule: authenticated()] when action in [:index, :show]
  plug Warden.Plug, [rule: role(:editor), authorizer: MyApp.Authz] when action in [:new, :create]

  def show(conn, %{"id" => id}) do
    post = Posts.get!(id)

    rule = any_of([permission("posts:read"), check(:owner)])

    # Resource-level check with the configured default authorizer...
    result = Warden.Plug.authorize(conn, rule, value: post)
    # ...or with an explicit one:
    # result = Warden.Plug.authorize(conn, rule, value: post, authorizer: MyApp.Authz)

    case result do
      {:ok, conn} -> render(conn, :show, post: post)
      {:error, _denial} -> conn |> put_status(:not_found) |> put_view(MyAppWeb.ErrorHTML) |> render(:"404")
    end
  end

  def update(conn, %{"id" => id, "post" => params}) do
    post = Posts.get!(id)

    # Raises Warden.ForbiddenError (rendered as 403) when denied. Explicit authorizer;
    # without `authorizer:` the configured default is used:
    #   conn = Warden.Plug.authorize!(conn, check(:owner), value: post)
    conn = Warden.Plug.authorize!(conn, check(:owner), value: post, authorizer: MyApp.Authz)
    {:ok, post} = Posts.update(post, params)
    redirect(conn, to: ~p"/posts/#{post}")
  end
end
```

`Warden.Plug.authorize/3` returns `{:ok, conn}` (the conn unchanged) or
`{:error, %Warden.Denial{}}` and sends nothing; `Warden.Plug.authorize!/3` returns the
conn or raises `Warden.ForbiddenError`. Both take `value:` and `authorizer:`.

## GraphQL

### Declaring rules

```elixir
defmodule MyApp.Schema do
  use Absinthe.Schema
  use Warden.Absinthe                            # configured default
  # use Warden.Absinthe, authorizer: MyApp.Authz # or explicit

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

`use Warden.Absinthe` must come after `use Absinthe.Schema`. In type modules pulled in with
`import_types`, add `use Warden.Absinthe.Notation` after `use Absinthe.Schema.Notation`.

#### Rules

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

#### Where rules apply

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

#### SDL schemas

Use `Warden.Absinthe.Hydrate.meta/2` in `hydrate/2`:

```elixir
def hydrate(%Absinthe.Blueprint.Schema.FieldDefinition{identifier: :email}, [%{identifier: :user} | _]) do
  [Warden.Absinthe.Hydrate.meta(rule: role(:admin))]
end
```

On an argument node (`InputValueDefinition` of a field), `rule:` is an argument rule.

Absinthe's `{:meta, ...}` hydration replaces the node's meta. Warden installs a hydrator
that keeps its own keys across a later `{:meta, ...}` and fails compilation when two
hydrations set a Warden key to different values. You can also pass your other meta as
the second argument: `Warden.Absinthe.Hydrate.meta([rule: role(:admin)], cache: false)`.

### Schema options

| Option | Default | Meaning |
|---|---|---|
| `authorizer` | configured default | Your `Warden.Authorizer` module: this option, else `config :warden, authorizer: ...`. |
| `strict_mode` | `false` | `false`, `:root` or `:all`; see below. |
| `default_object_rule` | `nil` | Rule for object types without their own rule (root and introspection types excluded). |
| `introspection` | `public()` | Rule that guards `__schema` and `__type` on every object Absinthe adds them to (any type named `Query` or `RootQueryType`, not only the root). `__typename` is guarded only by root object rules. |
| `list_policy` | `:null_item` | Default list policy. |

`default_object_rule: public()` does nothing except hide that a type has no rule. Do not
use it to silence strict mode.

#### `strict_mode`

Rules are optional by default: a field or type without a rule is allowed.

| Value | Compile-time requirement |
|---|---|
| `false` | none |
| `:root` | every field of the query, mutation and subscription types declares a rule (`public()` counts) |
| `:all` | every field of every object type declares a rule (an interface field rule counts); introspection excluded |

A missing rule is a `CompileError` that names every offending field. Introspection
fields are recognized by their GraphQL name (`__typename`, `__schema`, `__type`), so a
field whose identifier starts with `__` is an ordinary field.

### Denial handling

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

### List policies

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

### Subscriptions

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

### REST and the core API

- **Warden authorizes; your authentication decides who the user is.** The actor comes
  from `conn_context/1` (default: `conn.assigns`). Run your authentication plug before
  the first Warden plug, and never assign the user from params, headers or the body
  without verifying them.
- **No actor cache in the Plug.** Each Plug check builds the actor from the conn as it is
  at that moment, so changed assigns (logout, impersonation, a tenant switch) always
  apply. An actor you build with `Warden.actor/2` or `Warden.Plug.actor/2` and reuse
  keeps the roles it was built with; that is your choice.
- **Route rules do not cover resources.** `plug Warden.Plug, rule: ...` checks the actor,
  not the record. Use `Warden.Plug.authorize/3` with `value:` (or `Warden.filter/4` for
  lists) for record-level checks inside actions; queries that load records are still
  your code.
- **Denial responses.** The default sends 401 to anonymous and 403 to everyone else, so
  a client can tell "not logged in" from "not allowed". Return 404 from `on_deny` or
  `deny_conn/2` (or from the `{:error, _}` branch of `Warden.Plug.authorize/3`) where
  the existence of a resource is itself a secret.
- **Custom handlers.** A handler cannot let a denied request through: the plug halts
  whatever it returns. Code that runs in the handler itself (logging, redirects) is
  yours.
- **Hand-built actors** are refused by the core API; an actor must come from
  `Warden.actor/2` or `Warden.Plug.actor/2`. Warden does not read `conn.private`.
- **Inspect output.** `inspect/1` of `Warden.Actor`, `Warden.Denial` and
  `Warden.ForbiddenError` never shows the subject (the user record) or the guarded
  resource, so they stay out of logs and crash reports. Direct field access
  (`denial.actor.subject`) and `Map.from_struct/1` still expose them, on purpose.
- **The default authorizer is compile-time configuration** (`Application.compile_env`).
  A different value in `config/runtime.exs` stops the release at boot.

### GraphQL

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

`test/standalone/no_optional_deps_test.exs` builds throwaway Mix projects that depend on
Warden by path (without the optional dependencies, with only `plug`, with only
`absinthe`, and with only the configured default authorizer), compiles them with
warnings as errors and runs Warden in them. It is excluded by default:

```sh
mise exec -- mix test --only no_optional_deps
```

The property tests run 500 cases by default; set `WARDEN_PROPERTY_RUNS` for more.

Static checks (Dialyzer must report 0 warnings):

```sh
mise exec -- mix compile --warnings-as-errors --force
mise exec -- mix format --check-formatted
mise exec -- mix dialyzer
MIX_ENV=test mise exec -- mix dialyzer   # also covers test/support, like ElixirLS
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, the checks CI runs, and the commit
message format ([Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)).
