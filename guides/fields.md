# Field policies

A field policy says which fields of a struct an actor may read. You declare it once per
struct, and Warden applies it wherever the struct leaves your application: a GraphQL
object, a REST response, a webhook payload, a chat post, an export, a prompt.

Without it, every surface writes its own blank: the GraphQL resolver empties the body of
a deleted comment, and the webhook payload that forgot to is the leak.

Field policies are part of the core (no Ecto or Absinthe needed).

## Declaring a field policy

```elixir
defmodule MyApp.Authz.CommentFields do
  use Warden.Fields, authorizer: MyApp.Authz, for: MyApp.Comment

  # A deleted comment's body and anchor are blank for everyone, its author included.
  redact :body, with: "", unless: check(:live)
  redact :anchor, with: nil, unless: check(:live)
end

defmodule MyApp.Authz.UserCardFields do
  use Warden.Fields, authorizer: MyApp.Authz, for: MyApp.UserCard

  # A guest does not see a member's timezone.
  redact :timezone, with: nil, unless: tenant_role(:member)
end
```

`redact field, with: value, unless: rule`:

* `field` is a field of the `for:` struct. An unknown field, or a field named twice,
  fails compilation.
* `with:` is the value the field gets when the rule denies.
* `unless:` is any Warden rule, evaluated over the struct: checks get it as
  `Warden.Check.value`, and `tenant_role/1` asks about the struct's tenant
  (`c:Warden.Authorizer.tenant_of/1`). The field keeps its value only when the rule
  passes. The rule is validated against the authorizer's catalog at compile time.

A redaction rule is about the struct alone, so rules that read field arguments
(`tenant_role(r, tenant: {:arg, path})`, `can(policy, action, arg: path)`) and
`covered()` fail compilation: a client must never be able to pick an argument that
reveals a field.

## Registering it

The authorizer lists its field policies, like its policies:

```elixir
use Warden.Authorizer,
  roles: [:instance_admin],
  tenant_roles: [:owner, :admin, :member, :guest],
  fields: [MyApp.Authz.CommentFields, MyApp.Authz.UserCardFields],
  checks: [live: [batch: true, system_kinds: [:webhook]]]
```

The authorizer only names the modules, so it does not depend on them at compile time;
`use Warden.Fields` checks that its authorizer lists it. One struct has one field
policy: two policies for the same struct raise `Warden.PolicyError` when Warden looks
them up.

## Redacting

```elixir
Warden.redact(actor, comment)                   # the struct, denied fields replaced
Warden.redact(actor, comments)                  # a list, order kept
Warden.redact(actor, payload, deep: true)       # registered structs at any depth
Warden.visible_fields(actor, comment)           # MapSet of the fields left as they are
```

Like the rest of the core API, the first argument is an actor or a context map, and
`authorizer:` and `context:` work as in `Warden.authorize/3`.

* A struct without a field policy, and any other value, is returned as it is.
* A list: its registered structs are redacted, everything else is left in place.
* `deep: true` walks maps (keys and values), lists, tuples, `MapSet` elements (the set
  is rebuilt with `MapSet.new/1`) and structs. A struct without a field policy is
  rebuilt as the same struct with its fields walked, so a registered struct inside it
  is redacted too. `Ecto.Association.NotLoaded`, `Date`, `Time`, `NaiveDateTime`,
  `DateTime` and `Decimal` are left as they are. A registered struct is redacted before
  Warden walks its fields, so a field the policy replaced is not walked into.
* `visible_fields/2` counts a field as redacted when its rule denies, even when the value
  already equals the replacement.

### Lists and batching

The structs of one field policy are decided together: every rule runs once for all of
them with the same batching as `Warden.filter/4`. A batched check (`batch: true`) is
called once per rule and list, and tenant roles are read once per tenant. With
`deep: true`, each level of nesting is one batch: an issue list with its comments is
one call for the issues and one for all their comments.

```elixir
# One check_many(:live, ...) call for all 500 comments.
Warden.redact(actor, comments)
```

## Who sees what

Field policies use the same rules as everything else, so the same guarantees hold:

* **System actors.** A webhook or a job passes no role, no tenant role, no
  `authenticated()` and no check that does not name its kind (`system_kinds:`). Unless a
  rule says what its kind sees, it gets the redacted value:

  ```elixir
  redact :body, with: "", unless: check(:live)          # :live lists system_kinds: [:webhook]
  redact :email, with: nil, unless: role(:instance_admin)  # no system actor ever sees it
  ```

* **Delegation.** An agent acting on behalf of a user keeps a field only when both pass
  its rule.
* **Bound credentials.** A credential bound to tenant A has no tenant roles in any other
  tenant, so tenant-role redactions apply there.

```elixir
webhook = Warden.system_actor(MyApp.Authz, kind: :webhook, tenant: workspace.id)

webhook
|> Warden.filter(can(MyApp.Authz.Comments, :read), comments)
|> then(&Warden.redact(webhook, &1))
|> build_payload()
```

## GraphQL: `redact_with`

```elixir
object :comment do
  authorize can(MyApp.Authz.Comments, :read)
  redact_with MyApp.Authz.CommentFields

  field :body, non_null(:string)      # no custom resolver needed
  field :anchor, :string
end
```

Every object type over the struct (linked through a `can/2` policy's `for:` or
`warden_schema`) that exposes a redacted field under the same identifier must declare
`redact_with` for its field policy; otherwise the schema fails to compile. A type that
exposes none of the redacted fields needs nothing.

After the object rule passes and before any child field resolves, Warden replaces the
object value with its redacted struct. For an interface or union, Warden resolves the
concrete type again on the redacted struct; when redaction changed it, the value is
denied. Default resolvers and custom resolvers of the
child fields both read the redacted struct, so no field can reach the original value.

It applies wherever object rules apply: per list item (one decision per rule and list),
in nested lists, behind interfaces and unions, on Dataloader, `Async` and `Batch`
values, in mutation payloads, and on every subscription publish with the subscriber's
actor, so a role revoked between two events redacts the next one. With cross-parent
batching (`batch_across_parents: :auto`, the default, for batched rules), a single
comment under each item of a list is decided and redacted for all items at once.

Compile-time checks:

* the module must be a field policy of the schema's authorizer;
* when the object rule uses `can/2`, or the object names its schema with
  `warden_schema`, the field policy must be for that struct;
* `with: nil` on a field that the object declares non-null (same identifier) fails, as
  a `null` there would null the whole object;
* `redact_with` goes on object types only, once per type.

A value of another type than the policy's struct (a plain map, another struct) raises
`Warden.PolicyError`: Warden cannot tell which of its fields to hide, and shows nothing.

`redact_with` and `authorize rule, on_deny: ...` solve different problems: a field rule
decides whether the client may ask for a field at all (and what a denial looks like);
a field policy decides what the value is, the same in every front end.

## What redaction does not do

* It never writes anything. It returns new structs; the stored data stays as it was.
  Do not save a redacted struct back.
* It does not hide fields from introspection.
* Nothing Warden builds while redacting shows a redacted value: checks hide their value
  in `inspect/1`, telemetry carries no values, and errors name the policy and the struct
  module, never the value.

## Telemetry

Redaction emits `[:warden, :decision]` events with `layer: :fields` and `kind: :field`:
one per redaction rule and group of structs, with `count` (structs decided) and `denied`
(structs whose field was redacted). As everywhere, the metadata has no subject and no
value.
