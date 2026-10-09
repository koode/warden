# Contributing

Thanks for helping with Warden. This file explains how to set up the project, what to
check before you open a pull request, and how to write commit messages.

## Setup

The project uses [mise](https://mise.jdx.dev) to pin Erlang and Elixir in `mise.toml`.
Do not use another version manager or a global install.

```sh
mise trust && mise install
mise exec -- mix deps.get
```

## Before you open a pull request

Run these checks. All of them must pass.

```sh
mise exec -- mix format --check-formatted
mise exec -- mix compile --warnings-as-errors
MIX_ENV=test mise exec -- mix compile --warnings-as-errors
mise exec -- mix credo
mise exec -- mix test
mise exec -- mix test --only no_optional_deps
mise exec -- mix docs --warnings-as-errors
mise exec -- mix dialyzer
MIX_ENV=test mise exec -- mix dialyzer
```

CI runs the same checks. `mix test --only no_optional_deps` builds small throwaway
projects that depend on Warden without Absinthe, without Plug, or without both, so it
needs network access to Hex the first time.

- **Credo runs in strict mode with every [ExSlop](https://github.com/elixir-vibe/ex_slop)
  check** (`.credo.exs`). Fix a finding rather than disable it. If a check is wrong
  for one line, disable it for that line only and add a comment with the reason.
- **Dialyzer must report 0 warnings in both the dev and the test env.** The test env
  also analyzes `test/support`, the same way ElixirLS does. Do not add an ignore file.
- **New logic needs tests.** Put them in `test/`. Security behaviour also needs an
  adversarial test in `test/adversarial/`, named after the attack it stops.
- **Keep the core free of optional dependencies.** Code in `Warden`, `Warden.Rule`,
  `Warden.Authorizer`, `Warden.Actor`, `Warden.Check` and `Warden.Denial` must not call
  Absinthe or Plug. Code that needs them goes under `Warden.Absinthe` or `Warden.Plug`.
- **Show both ways to choose an authorizer** in every doc example of an entry point:
  the configured default and the explicit `authorizer:` option.
- **Update `CHANGELOG.md`** under an `## Unreleased` heading for changes that users
  can see.

## Security changes

Warden is an authorization library, so a bug can expose data that should stay hidden.

- Fail closed. When the input is unexpected (a callback returns a value that is not
  `true` or `false`, a rule names an unknown role), raise or deny. Never grant.
- Run the property tests with more cases before you open a pull request that changes
  `lib/`:

  ```sh
  WARDEN_PROPERTY_RUNS=5000 WARDEN_REDTEAM_RUNS=20000 mise exec -- mix test test/property test/redteam_fuzz
  ```

- Never weaken an existing test in `test/adversarial/` or `test/redteam*/` to make a
  change pass. If a test asserts the wrong behaviour, explain why in the pull request.
- Report a vulnerability privately to the maintainers, not in a public issue.

## Commit messages

This project uses [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Every commit on `main` follows this format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

The scope, body and footer are optional.

### Types

| Type | Use it for |
|---|---|
| `feat` | A new feature or option that users can see |
| `fix` | A bug fix, including a security fix |
| `docs` | Documentation only: README, guides, module docs |
| `test` | Tests only |
| `refactor` | A code change that does not change behaviour |
| `perf` | A change that makes something faster or smaller |
| `build` | Hex dependencies, package metadata, tool configuration |
| `ci` | CI configuration |
| `style` | Formatting only |
| `chore` | Other maintenance, for example tool versions or releases |
| `revert` | Reverts an earlier commit |

### Scopes

Use a scope when the change is in one area:

| Scope | Area |
|---|---|
| `core` | `Warden`, `Warden.Rule`, `Warden.Authorizer`, `Warden.Actor`, `Warden.Check`, `Warden.Denial` and the errors |
| `absinthe` | `Warden.Absinthe` and the modules under it |
| `plug` | `Warden.Plug` |
| `deps` | Dependency updates |
| `hex` | Hex package metadata |
| `release` | Release commits |

### Subject and body

- Write the subject in the imperative mood, in lower case, with no period at the end:
  `fix(plug): build the actor from the current conn on every check`.
- Keep the subject line to 72 characters or fewer.
- Use the body to explain why the change is necessary, not what each line does.
- Refer to issues in the footer, for example `Closes #12`.

### Breaking changes

Mark a breaking change with `!` after the type or scope, and explain it in a
`BREAKING CHANGE:` footer:

```
feat(absinthe)!: rename Warden.Schema to Warden.Absinthe

BREAKING CHANGE: replace `use Warden.Schema` with `use Warden.Absinthe`.
```

Before 1.0.0, a breaking change increments the minor version (0.1.x to 0.2.0).

## Pull requests

- Keep one topic per pull request.
- Rebase on `main` before you ask for a review. History on `main` is linear: no merge
  commits and no squash merges, so every commit must pass the checks on its own and
  have a Conventional Commits message.
- Describe what changed and how you tested it.

## Releases

Maintainers make releases:

1. Set the new version in `mix.exs` and move the `## Unreleased` entries in
   `CHANGELOG.md` under the new version.
2. Commit with `chore(release): vX.Y.Z`.
3. Tag the commit with `git tag -a vX.Y.Z -m vX.Y.Z` and push the branch and the tag.
4. Run `mise exec -- mix hex.publish`.

## License

By contributing, you agree that your contributions are licensed under the MIT
license in `LICENSE`.
