defmodule XirsysTurnServer.Mixfile do
  use Mix.Project

  def project() do
    [
      apps_path: "apps",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  defp deps() do
    [
      {:dialyze, ">= 0.1.4"},
      {:ex_doc, "~> 0.18.3"},
      {:distillery, "~> 1.5", runtime: false}
    ]
  end
end
