# Credo with every ExSlop check, including the opt-in ones.
%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "test/", "config/", "mix.exs"],
        excluded: [~r"/_build/", ~r"/deps/"]
      },
      strict: true,
      checks: %{extra: Enum.map(ExSlop.checks(), &{&1, []})}
    }
  ]
}
