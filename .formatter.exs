locals_without_parens = [authorize: 1, authorize_args: 1, list_policy: 1]

[
  import_deps: [:absinthe],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  locals_without_parens: locals_without_parens,
  export: [locals_without_parens: locals_without_parens]
]
