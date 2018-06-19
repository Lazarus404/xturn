defmodule Xturn.Mixfile do
  use Mix.Project

  def project() do
    [ app: :xturn,
      version: "0.0.1",
      elixir: "~> 1.3.2",
      name: "xturn",
      source_url: "https://github.com/xirdev/xturn",
      escript: [ main_module: Xirsys.Turn ],
      deps: deps() ]
  end

  def application() do
    [ applications: [:crypto,
                     :sasl,
                     :logger,
                     :ssl,
                     :xmerl,
                     :exts
                    ],
      registered: [ Xirsys.Turn.Server ],
      mod: { Xirsys.Turn, [] },
      logger: [ compile_time_purge_level: :debug ],
      env: [
            node_name: "xturn",
            node_host: "localhost",
            cookie: :IAMACOOKIEMONSTER
      ]
    ]
  end

  defp deps() do
    [ {:ex_doc,      "~> 0.18.3"},
      {:exts,        "~> 0.3.4"},
      {:xturnlib,    in_umbrella: true},
      {:poolboy,     "~> 1.5", override: true},
      {:maru,        "~> 0.13"},
      {:cowboy,      "~> 2.3"} ]
  end
end
