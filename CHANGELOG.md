# Changelog

## Unreleased

### Added

- Actor kinds (`kinds:`, `c:Warden.Authorizer.kind/2`, `kind/1` rule), credentials
  (`Warden.Credential`, `c:Warden.Authorizer.credential/1`, `credential_scopes:`,
  `session/0` and `credential_scope/1` rules) and tenant roles (`tenant_roles:`,
  `tenant_role_hierarchy:`, `c:Warden.Authorizer.tenant_roles/3`, `tenant_role/1,2`),
  read at most once per actor and tenant and cached in the actor struct.
- `c:Warden.Authorizer.tenant_of/1`, `c:Warden.Authorizer.tenants/2`,
  `Warden.Actor.tenants/2` and `Warden.Actor.preload_tenant_roles/3`.
- A credential bound to a tenant denies every tenant role, policy and scope for any other
  tenant without calling the authorizer or the policy.
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
- Absinthe: `covered()`, `authorize rule, on_deny: ...`, `can/2,3` as object, field
  and argument rules, and opt-in `batch_across_parents: true`.
- The core API takes an `args:` option.
- `Warden.Phoenix.Channel` for Phoenix channels: a rule checked at join, before every
  push (`recheck: :every_push`) and on a timer (`{:every, ms}`), with a fresh actor
  from the new authorizer callback `socket_context/1` on every check. A denial stops the
  channel with a reason the client can show.
- `guides/actors.md` and `guides/channels.md`.

### Changed

- `default_actor_key/1` also covers the kind, the credential, system actors, bounds and
  the delegator. The key of a plain user actor is unchanged.
- `inspect/1` of an actor shows its kind, whether it is a system actor, the credential
  method and scopes, and the delegator's kind; of a denial, its reason (atoms only).
- In GraphQL, an object value admitted by a batched object rule is not decided again by
  the pre middleware of each of its fields, so a list stays one batched call.
- `Warden.Plug` sends 403 (not 401) for a denied system actor.

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
