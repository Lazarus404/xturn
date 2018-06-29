use Mix.Config

config :logger,
  level: :debug,
  compile_time_purge_level: :debug

config :xturn,
  authentication: %{required: true},
  permissions: %{required: false},
  realm: "xirsys.com",
  listen: [
            {:udp, '185.136.235.163', 3478},
            {:tcp, '185.136.235.163', 3478},
            # {:udp, '0.0.0.0', 80},
            # {:tcp, '0.0.0.0', 80},
            {:udp, '185.136.235.163', 5349, :secure},
            {:tcp, '185.136.235.163', 5349, :secure}#,
            # {:udp, '0.0.0.0', 443, :secure},
            # {:tcp, '0.0.0.0', 443, :secure}
          ],
  server_type: "turn",
  server_id: "turn.tstitch.me",
  certs: [
           {:certfile, "certs/server.crt"},
           {:keyfile, "certs/server.key"}
         ]

config :maru, Xirsys.API,
  http: [port: 8880]

