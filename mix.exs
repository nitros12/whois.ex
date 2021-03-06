defmodule Whois.Mixfile do
  use Mix.Project

  def project do
    [
      app: :whois,
      version: "0.2.2",
      elixir: "~> 1.2",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description: "Pure Elixir WHOIS client and parser.",
      package: package()
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [{:ex_doc, "~> 0.18.1", only: :dev},
     {:timex, "~> 3.1"}
    ]
  end

  defp package do
    [
      maintainers: ["Utkarsh Kukreti"],
      licenses: ["MIT"],
      links: %{GitHub: "https://github.com/utkarshkukreti/whois.ex"}
    ]
  end
end
