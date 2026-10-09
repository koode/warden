defmodule Warden.MixProject do
  use Mix.Project

  @version "0.1.0"

  # The Absinthe requirement can be overridden to run the suite against an older
  # Absinthe, together with a matching lockfile:
  #
  #     ABSINTHE_VERSION="1.7.10" MIX_LOCKFILE=mix.lock.absinthe17 mix test
  @absinthe_requirement System.get_env("ABSINTHE_VERSION", ">= 1.7.0")

  def project do
    [
      app: :absinthe_warden,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      lockfile: System.get_env("MIX_LOCKFILE", "mix.lock"),
      deps: deps(),
      description: "Role- and permission-based authorization for Absinthe GraphQL.",
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
      {:absinthe, @absinthe_requirement},
      {:stream_data, "~> 1.1", only: :test},
      {:dataloader, "~> 2.0", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "docs/DESIGN.md"]
    ]
  end
end
