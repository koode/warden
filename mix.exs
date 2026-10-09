defmodule Warden.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/koode/warden"

  def project do
    [
      app: :warden,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description:
        "Role- and permission-based authorization for Elixir, with Absinthe and Plug integrations.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:absinthe, "~> 1.12", optional: true},
      {:plug, "~> 1.14", optional: true},
      {:stream_data, "~> 1.1", only: :test},
      {:dataloader, "~> 2.0", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_slop, "~> 0.4", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "warden",
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE docs/DESIGN.md .formatter.exs)
    ]
  end

  # PLTs live in priv/plts so CI can cache them (see .github/workflows/ci.yml).
  defp dialyzer do
    [
      plt_core_path: "priv/plts",
      plt_local_path: "priv/plts",
      flags: [:error_handling, :extra_return, :missing_return, :unmatched_returns],
      plt_add_apps: [:ex_unit]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      extras: ["README.md", "docs/DESIGN.md", "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE"]
    ]
  end
end
