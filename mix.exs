defmodule Xirsys.XTurn.Mixfile do
  use Mix.Project

  @version "2.0.0"
  @source_url "https://github.com/Lazarus404/xturn"

  def project() do
    [
      app: :xturn,
      version: @version,
      elixir: ">= 1.16.0",
      name: "xturn",
      description: description(),
      source_url: @source_url,
      homepage_url: @source_url,
      elixirc_paths: elixirc_paths(Mix.env()),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs(),
      aliases: [test: ["test --no-start"]]
    ]
  end

  def application() do
    [
      mod: {Xirsys.XTurn, []},
      registered: [Xirsys.XTurn.Server],
      included_applications: [:maru],
      env: [
        node_name: "xturn",
        node_host: "localhost",
        cookie: :IAMACOOKIEMONSTER
      ]
    ]
  end

  defp description do
    "Elixir STUN/TURN relay server for WebRTC -- UDP, TCP, TLS, and DTLS listeners with long-term and shared-secret auth."
  end

  defp deps() do
    [
      {:xsockets, "~> 1.0"},
      {:xmedialib, "~> 0.3"},
      {:xturn_plugin_api, "~> 0.1"},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:exts, "~> 0.3.4"},
      {:maru, "~> 0.13"},
      {:jason, "~> 1.0"},
      {:plug, "~> 1.14"},
      {:cowboy, "~> 2.18"},
      {:cowlib, "~> 2.20"},
      {:plug_cowboy, "~> 2.9"},
      {:telemetry, "~> 1.0"}
    ]
  end

  defp package do
    %{
      name: "xturn",
      files: [
        "lib",
        "mix.exs",
        "README.md",
        "LICENSE.md",
        "CHANGELOG.md",
        "ARCHITECTURE.md",
        "PLUGIN.md",
        "config"
      ],
      maintainers: ["Jahred Love"],
      licenses: ["BSD-3-Clause"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md",
        "HexDocs" => "https://hexdocs.pm/xturn"
      }
    }
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "ARCHITECTURE.md",
        "PLUGIN.md",
        "CHANGELOG.md",
        "LICENSE.md"
      ],
      groups_for_extras: [
        Guides: ["ARCHITECTURE.md", "PLUGIN.md"],
        "Release notes": ["CHANGELOG.md"]
      ],
      groups_for_modules: [
        Entry: [Xirsys.XTurn, Xirsys.API],
        Listen: [
          Xirsys.XTurn.ListenConfig,
          Xirsys.XTurn.ListenRegistry,
          Xirsys.XTurn.DatagramListener,
          Xirsys.XTurn.Handlers.StunTurn,
          Xirsys.XTurn.Handlers.SocketPipeline,
          Xirsys.XTurn.Accumulators.StunTurn
        ],
        Control: [
          Xirsys.XTurn.Pipeline,
          Xirsys.XTurn.Conn,
          Xirsys.XTurn.Binding,
          Xirsys.XTurn.Response,
          Xirsys.XTurn.ClientWorker,
          Xirsys.XTurn.ClientWorker.Pool
        ],
        Allocate: [
          Xirsys.XTurn.Allocate.Client,
          Xirsys.XTurn.Allocate.Store,
          Xirsys.XTurn.Allocate.Supervisor,
          Xirsys.XTurn.ClientSocket,
          Xirsys.XTurn.Channels.Store,
          Xirsys.XTurn.Permissions.Store
        ],
        "Data plane": [
          Xirsys.XTurn.DataPlane,
          Xirsys.XTurn.RelayIngress,
          Xirsys.XTurn.RelayIngress.Worker
        ],
        Auth: [
          Xirsys.XTurn.Auth.Client,
          Xirsys.XTurn.Auth.SharedSecret,
          Xirsys.XTurn.Auth.AccessToken,
          Xirsys.XTurn.Auth.NonceStore
        ],
        Plugins: [
          Xirsys.XTurn.Plugin.Manager,
          Xirsys.XTurn.Plugin.Dispatch,
          Xirsys.XTurn.Plugin.Lifecycle,
          Xirsys.XTurn.Plugin.Chain,
          Xirsys.XTurn.Plugin.Table,
          Xirsys.XTurn.Plugin.Instance
        ]
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
