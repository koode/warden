locals_without_parens = [
  actor: 2,
  allow: 2,
  authorize: 1,
  authorize_args: 1,
  list_policy: 1,
  redact: 2,
  redact_with: 1,
  requires: 2,
  resource: 2,
  warden_schema: 1
]

[
  import_deps: [:absinthe],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  locals_without_parens: locals_without_parens,
  export: [locals_without_parens: locals_without_parens]
]
