defmodule Warden.MixProject do
  use Mix.Project

  @version "0.1.0"

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
      docs: docs(),
      dialyzer: [
        flags: [:error_handling, :extra_return, :missing_return, :unmatched_returns],
        plt_add_apps: [:ex_unit]
      ]
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
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "warden",
      licenses: ["MIT"],
      links: %{},
      files: ~w(lib mix.exs README.md docs/DESIGN.md .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "docs/DESIGN.md"]
    ]
  end
end
