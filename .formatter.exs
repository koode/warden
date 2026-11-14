# The notation apps write in schemas, policies and field policies; exported to apps that
# list :warden in `import_deps`.
exported = [
  allow: 2,
  authorize: 1,
  authorize: 2,
  authorize_args: 1,
  list_policy: 1,
  redact: 2,
  redact_with: 1,
  requires: 2,
  warden_schema: 1
]

# `actor` and `resource` of `Warden.Test.Matrix` are common names, so they are not
# exported; this repository's tests use them without parentheses.
test_only = [actor: 2, resource: 2]

[
  import_deps: [:absinthe],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  locals_without_parens: exported ++ test_only,
  export: [locals_without_parens: exported]
]
