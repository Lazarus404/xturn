defmodule Xirsys.XTurnLib.Mixfile do
  use Mix.Project

  def project() do
    [ app: :xturnlib,
      version: "0.0.1",
      elixir: "~> 1.0",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      deps: deps() ]
  end

  def application() do
    [ applications: [ :logger ] ]
  end

  defp deps() do
    []
  end
end
