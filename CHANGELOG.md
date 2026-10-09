# Changelog

## Unreleased

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
