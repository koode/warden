# Testing policies

Behaviour tests come one at a time, usually after a leak: a guest saw a private team's
comment, an API key reached a code review. Nothing fails when a new resource, surface or
actor kind ships without that coverage.

Warden knows every policy, action and redacted field, so it can test all of them at
once. Three helpers do that:

* `Warden.Test.assert_policy_consistent/4` proves that one policy gives the same answer
  everywhere, for the actors and rows you pass;
* `Warden.Test.Matrix` builds every actor against every resource from fixtures, checks
  each cell and compares the result with a readable snapshot (needs `ecto`);
* `Warden.Test.Absinthe.assert_matrix_matches/2` runs the same cells through GraphQL
  (needs `absinthe`).

Failures raise `ExUnit.AssertionError` and name fixtures, positions, policies and
fields, never a subject or row data. Nothing in Warden loads ExUnit unless one of these
helpers is called, so they can live in `lib/` of a library.

## One policy: `assert_policy_consistent/4`

```elixir
test "the issue policy agrees with itself" do
  Warden.Test.assert_policy_consistent(
    MyApp.Authz.Issues,
    [owner: owner_context, guest: guest_context, webhook: webhook_actor],
    [public_issue: public_issue, private_issue: private_issue]
  )
end
```

For every actor, row and action of the policy it compares:

* for a `Warden.Ecto.Policy`: `Warden.Ecto.allowed?/4` on the struct (which the policy's
  hand-written `allowed?/4` answers when it has one), `Warden.Ecto.allowed?/4` on
  `{schema, id}`, membership in `Repo.all(Warden.Ecto.scope(...))`, and membership in
  `Warden.Ecto.filter/4`;
* for a `Warden.Policy`: `can(policy, action)` on the value alone and over the list.

A disagreement fails with the cell and which ways allowed or denied:

```
MyApp.Authz.Notes gives different answers in 1 cell(s):
  actor member, resource secret_note, action :read: allowed?/4 (hand-written), filter/3 allow; allowed?/3 by id, scope/4 deny
```

Unnamed actors and rows are named by position (`actor 1`, `row 2`). On success it
returns `%{{actor_name, row_name, action} => allowed?}`. Options: `:authorizer`,
`:repo` (default: the policy's `:repo`) and `:actions`.

## Every policy: `Warden.Test.Matrix`

```elixir
defmodule MyApp.AuthzMatrixTest do
  use Warden.Test.Matrix,
    authorizer: MyApp.Authz,
    repo: MyApp.Repo,
    snapshot: "test/authz/matrix.snapshot"

  actor :owner, &Fixtures.owner/1
  actor :member, &Fixtures.member/1
  actor :guest, &Fixtures.guest/1
  actor :outsider, &Fixtures.other_workspace_member/1
  actor :api_key_read, &Fixtures.api_key(&1, ["issues:read"])
  actor :webhook, &Fixtures.team_webhook/1

  resource :team_private, &Fixtures.team(&1, private: true)
  resource :issue_private_team, fn %{warden_fixtures: fixtures} ->
    Fixtures.issue(team: fixtures.team_private)
  end
  resource :comment_deleted, &Fixtures.comment(&1, deleted: true)
end
```

`import_deps: [:warden]` does not export `actor/2` and `resource/2`: they are common
names, and keeping them out stops the formatter from dropping parentheses from your own
functions. To write them without parentheses in tests only, give `test/` its own
formatter file and list it in the root one:

```elixir
# .formatter.exs
[
  import_deps: [:warden],
  subdirectories: ["test"],
  inputs: ["{mix,.formatter}.exs", "{config,lib}/**/*.{ex,exs}"]
]

# test/.formatter.exs (a subdirectory file inherits nothing, so import :warden again)
[
  import_deps: [:warden],
  inputs: ["**/*.{ex,exs}"],
  locals_without_parens: [actor: 2, resource: 2]
]
```

The module is an `ExUnit.Case` with one test, `"policy matrix"`, tagged
`:warden_matrix`. It:

1. checks out the SQL sandbox (`sandbox: false` when your own setup does);
2. runs your module's `setup` blocks;
3. builds the fixtures in the order you declared them; each fixture function gets the
   ExUnit context with the fixtures built before it under `:warden_fixtures`;
4. for every actor, every resource and every action of that resource's policy, checks
   consistency as `assert_policy_consistent/4` does and records the allowed actions;
5. records the fields `Warden.redact/3` changes, for cells where the actor may take an
   action and the struct has a field policy;
6. compares the matrix with the snapshot.

An actor fixture returns an actor (`Warden.actor/2`, `Warden.system_actor/2`,
`Warden.on_behalf_of/3`) or a context map; system actors and delegated actors are
columns like any other. A resource fixture returns a persisted struct. Actions are
taken from the resource's own policy, so actions that do not apply to a resource never
show up as denied.

Every policy in the authorizer's `policies:` needs at least one resource, and every
resource needs a policy; otherwise the test fails and names them:

```
the policy matrix is incomplete:
  MyApp.Authz.Labels has no resource fixture
```

That is the point of the matrix: a new resource cannot ship without being placed in
it.

### The snapshot

```
# Warden policy matrix: the actions each actor (column) may take on each resource
# (row); "-" means none. Fixture names only. Rewrite with `mix warden.matrix --update`.

policy MyApp.Authz.Issues
actions read read_trashed write
resource            api_key_read  guest  member      outsider  owner                    webhook
issue_private_team  read          -      read,write  -         read,read_trashed,write  read

redacted
resource         actor  fields
comment_deleted  guest  body
```

Policies, resources, actors, actions and fields are sorted, so the same matrix always
writes the same file and a review diff shows only real changes. The file holds fixture
names, policy modules and field names only.

When the matrix differs from the snapshot, the test fails with the changed cells only:

```
the policy matrix differs from test/authz/matrix.snapshot in 2 cell(s):
  resource issue_private_team, actor guest: snapshot -, now read
  resource comment_deleted, actor guest redacted fields: snapshot body, now none
Run `mix warden.matrix --update` if the change is intended.
```

A difference in layout alone (column widths) is not a change.

### `mix warden.matrix`

```
mix warden.matrix               # print the tables, to paste into a review
mix warden.matrix --update      # rewrite the snapshot files
mix warden.matrix test/authz    # only the matrix tests under a path
```

The task runs `mix test --only warden_matrix` in the test environment with
`WARDEN_MATRIX=print` or `WARDEN_MATRIX=update`; the matrix test reads that variable.
Consistency failures still fail the run. Other arguments go to `mix test`.

`--only` includes the matrix tests even when another of their tags is excluded in your
`test_helper.exs`. If the helper prepares something only for such a tag (a database for
`:postgres`, say), prepare it when `:warden_matrix` is included too.

## GraphQL: `Warden.Test.Absinthe.assert_matrix_matches/2`

The policy can be right while the schema uses a weaker object rule, or forgets
`redact_with`. Run the matrix through GraphQL in a test of the same module:

```elixir
test "GraphQL agrees with the policies", %{warden_matrix: matrix} do
  Warden.Test.Absinthe.assert_matrix_matches(MyAppWeb.Schema,
    matrix: matrix,
    query_for: %{
      issue: "query($id: ID!) { issue(id: $id) { id title } }",
      comment: "query($id: ID!) { comment(id: $id) { id body } }"
    }
  )
end
```

For every GraphQL type in `query_for:`, every resource whose struct the type is linked
to (by `warden_schema` or a `can/2` object rule) and every actor that is a context map,
it runs the document with the row's primary key as `$id` and asserts:

* the root field returns the object exactly when the policy allows `:read` (or the
  `action:` you pass);
* every selected field that `Warden.redact/3` changes holds the redacted value (`nil`,
  strings, booleans and integers are compared).

```
GraphQL disagrees with the policies in 1 cell(s):
  actor outsider, resource issue_private_team, type :issue: the policy denies :read, GraphQL returned the object
```

GraphQL builds its actor from the context, so `%Warden.Actor{}` fixtures (system and
delegated actors) are left out. Without a matrix, pass `:authorizer`, `:actors` and
`:resources` as for `assert_policy_consistent/4`.
