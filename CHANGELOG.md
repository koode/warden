# Changelog

## Unreleased

## 0.2.0 (2026-11-14)

### Added

- Actor kinds (`kinds:`, `c:Warden.Authorizer.kind/2`, `kind/1` rule), credentials
  (`Warden.Credential`, `c:Warden.Authorizer.credential/1`, `credential_scopes:`,
  `session/0` and `credential_scope/1` rules) and tenant roles (`tenant_roles:`,
  `tenant_role_hierarchy:`, `c:Warden.Authorizer.tenant_roles/3`, `tenant_role/1,2`),
  read at most once per actor and tenant and cached in the actor struct.
- `c:Warden.Authorizer.tenant_of/1`, `c:Warden.Authorizer.tenants/2`,
  `Warden.Actor.tenants/2` and `Warden.Actor.preload_tenant_roles/3`.
- A credential (or system actor) bound to a tenant denies every rule except `public()`
  and `covered()` on a value of another tenant, with reason `:tenant_binding`, without
  calling the authorizer or the policy; batched checks never receive such values.
- `Warden.system_actor/2`: system actors that are never anonymous and never users.
- `Warden.on_behalf_of/3`: delegation that evaluates every rule for both actors and ANDs
  the results.
- `Warden.Policy` and the `can/2,3` rule, with `allowed?/4` and an optional
  `allowed_many/4` for lists; `arg:` asks about `{schema, id}` before the resolver.
- Checks declared as `name: options`: an option schema (`opts:`, `required:`),
  `batch: true` with `c:Warden.Authorizer.check_many/2`, `timeout:` (a timeout denies
  with reason `:unavailable`) and `system_kinds:`.
- Checks may return `{:deny, reason}`. `Warden.Denial` gains `reason` and `trace`;
  the default denial handler exposes atom reasons only with `expose_denial_reasons: true`.
- `Warden.explain/3` and `Warden.Explanation`.
- Telemetry: one `[:warden, :decision]` event per decision call (`Warden.Telemetry`).
- `Warden.filter/4` and GraphQL lists decide batched checks and policies once per list.
- Absinthe: `covered()`, `authorize rule, on_deny: ...`, `can/2` as object, field and
  argument rules (`can/3` with `arg:` in field and argument rules only), and opt-in
  `batch_across_parents: true`. Object rules that read field arguments fail compilation.
- The core API takes an `args:` option.
- `Warden.Phoenix.Channel` for Phoenix channels: a rule checked at join, before every
  push (`recheck: :every_push`) and on a timer (`{:every, ms}`), with a fresh actor
  from the new authorizer callback `socket_context/1` on every check. A denial stops the
  channel with a reason the client can show.
- Field policies: `use Warden.Fields, authorizer:, for:` with
  `redact field, with: value, unless: rule`, registered in the authorizer's new `fields:`
  option. Unknown fields and rules outside the catalog fail compilation.
- `Warden.redact/3` (a struct, a list, or with `deep: true` every registered struct at
  any depth: in maps, map keys, lists, tuples, MapSets and other structs) and `Warden.visible_fields/3`. Lists are decided once per rule,
  so a batched check runs once per list. Telemetry reports them as layer `:fields`.
- Absinthe: `redact_with FieldsModule` on an object type replaces the object value with
  its redacted struct after the object rule passes and before any child field resolves,
  on every subscription publish too. `with: nil` on a non-null field, a module that is
  not a field policy of the schema's authorizer, and a field policy for another struct
  than the object's `can/2` policy fail compilation, and so does an object type over a
  struct with a field policy that exposes a redacted field without `redact_with`. `Warden.Absinthe.Hydrate.meta/2`
  takes `redact_with:`.
- `guides/actors.md`, `guides/channels.md` and `guides/fields.md`.
- `Warden.Ecto.Policy` (needs `ecto`): one policy per schema and action, as a
  hand-written `scope/4` or as declarative `allow` and `requires` clauses (`rule:`,
  `where:`, `through:` with `if_nil:`, `through_any:`, `none:`, `actor_in:`,
  `member_of:`, `grant:`, `through_type:`, `within:`, `when:`), with options `schema:`,
  `as:`, `tenant:`, `null_tenant:`, `repo:`, `system_kinds:`, `subject_id:` and
  `write_actions:`. Clause errors fail compilation; errors across policies (a `through`
  to a schema without a policy, a cycle) warn after compiling and raise on first use.
- `Warden.Ecto`: `scope/3,4` (one tenant, or every tenant of the actor ORed),
  `allowed?/3,4`, `authorize/3,4` and `filter/3,4` on loaded structs and `{schema, id}`,
  `allowed_actors/3,4`, `explain/3,4`, `dataloader_query/2`, `to_sql/4` (needs
  `ecto_sql`), and `update_all/4` and `delete_all/3`, which refuse a query that was not
  scoped for a write action, a shadowing CTE, and updates of the tenant field or a
  `through:` field. `scope/4` refuses unions and preloads; checks decide loaded structs
  against their own query prefix. Telemetry with `layer: :ecto`.
- `can/2` with a `Warden.Ecto.Policy` decides a list with one query per tenant
  (`WHERE id = ANY($1) AND scope`); loaded structs are decided in memory where the
  clauses allow it.
- Absinthe: `require_can_for: [Schema, ...]` (with `strict_mode: :all`) and the
  `warden_schema Schema` notation on object types.
- `guides/policies-and-ecto.md`.
- Test helpers: `Warden.Test.assert_policy_consistent/4` (every way Warden answers a
  policy agrees, per actor, row and action), `Warden.Test.Matrix` (needs `ecto`: actor
  and resource fixtures, every policy needs a resource, a sorted snapshot of fixture
  names whose differences name the changed cells only),
  `Warden.Test.Absinthe.assert_matrix_matches/2` (needs `absinthe`: object rules and
  `redact_with` agree with the policies) and `mix warden.matrix [--update]`.
- The formatter exports `allow/2`, `requires/2`, `warden_schema/1`, `actor/2` and
  `resource/2` without parentheses.
- `guides/testing.md`.

### Changed

- `default_actor_key/1` also covers the kind, the credential, system actors, bounds and
  the delegator. The key of a plain user actor is unchanged.
- `inspect/1` of an actor shows its kind, whether it is a system actor, the credential
  method and scopes, and the delegator's kind; of a denial, its reason (atoms only).
- In GraphQL, an object value admitted by a batched object rule is not decided again by
  the pre middleware of each of its fields, so a list stays one batched call. A value
  redacted by `redact_with` is admitted as its fields see it (redacted), whatever its
  object rule: that rule was decided on the value before redaction.
- `Warden.Plug` sends 403 (not 401) for a denied system actor.
- Error messages describe guarded values and policy answers by shape (type, struct name,
  length), never by content.
- New required dependency: `telemetry`. New optional dependencies: `ecto`, `ecto_sql`
  and `phoenix`.

## 0.1.0 (2026-10-09)

First release.

- One authorizer module (`use Warden.Authorizer`) with a role catalog, role hierarchy,
  role-to-permission map, custom checks (`check/2`) and denial handling. Unknown roles,
  permissions and checks fail compilation.
- Rules as data: `public/0`, `authenticated/0`, `role/1`, `any_role/1`, `permission/1`,
  `all_permissions/1`, `any_permission/1`, `check/1,2`, `all_of/1`, `any_of/1` and
  `deny/0`. Only a literal `true` from a check grants access.
- Core API for any Elixir code: `Warden.actor/2`, `Warden.authorize/3`,
  `Warden.allowed?/3`, `Warden.authorize!/3` (raises `Warden.ForbiddenError`, rendered
  as 403 by Phoenix) and `Warden.filter/4`.
- `Warden.Plug` for Plug and Phoenix: route rules validated at compile time, resource
  checks with `Warden.Plug.authorize/3`, 401 for anonymous and 403 for other denials,
  and a denial handler that cannot let a request through.
- `Warden.Absinthe` for Absinthe schemas: rules on fields, object types, interfaces,
  unions, arguments and input fields. Denied data becomes `null`, folded to the nearest
  nullable parent. Queries, mutations and subscriptions are enforced the same way;
  subscriptions are checked at subscribe time and on every publish.
- Opt-in `strict_mode` (`:root` or `:all`) that requires a rule on every root field or
  every field.
- A default authorizer from `config :warden, authorizer: MyApp.Authz`, and an explicit
  `authorizer:` option on every entry point.
- Absinthe and Plug are optional dependencies.
- The Absinthe layer requires Absinthe 1.12.
