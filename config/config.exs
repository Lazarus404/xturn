import Config

config :xsockets,
  config_app: :xturn,
  # xturn owns SockSupervisor / TierSupervisor in its tree; do not double-start.
  start_supervisors: false,
  # xturn applies control-plane budgets in handlers; do not also gate the Engine.
  engine_rate_limit: false

config :logger, level: :info

config :xturn,
  telemetry_enabled: false,
  packet_log_enabled: false,
  udp_listen_shards: max(System.schedulers_online(), 1),
  packet_log_path: "log/packets.log",
  authentication: %{required: true},
  nonce_max_age_ms: 3_600_000,
  shared_secret: [
    enabled: false,
    secret: nil,
    default_ttl_seconds: 86_400
  ],
  permissions: %{required: true},
  realm: "xirsys.com",
  listen: [
    {:udp, ~c"0.0.0.0", 3478},
    {:tcp, ~c"0.0.0.0", 3478},
    {:udp, ~c"::", 3478},
    {:tcp, ~c"::", 3478},
    {:udp, ~c"0.0.0.0", 5349, :secure},
    {:tcp, ~c"0.0.0.0", 5349, :secure},
    {:udp, ~c"::", 5349, :secure},
    {:tcp, ~c"::", 5349, :secure}
  ],
  # Advertised IPv4 in XOR-RELAYED-ADDRESS / XOR-MAPPED-ADDRESS. Override with
  # XTURN_SERVER_IP at runtime or set your public/LAN address here.
  server_ip: {127, 0, 0, 1},

  ## RFC 5780 dual-IP (optional; both required to arm OTHER-ADDRESS / CHANGE-REQUEST):
  # other_ip: {192, 168, 0, 7},
  # other_port: 3479,
  # stun_port: 3478,

  ## RFC 3489 pt.12.2 cookie-less UDP Binding (default false):
  # rfc3489_compat: false,

  ## RFC 7635 third-party authorization (default false):
  # third_party_auth: [enabled: false, as_uri: nil, aead_key: nil, server_name: nil],

  server_local_ip: {0, 0, 0, 0},
  server_ip6: {0, 0, 0, 0, 0, 0, 0, 1},
  server_local_ip6: {0, 0, 0, 0, 0, 0, 0, 0},
  # TLS/DTLS material for :secure listeners. Point at your real certs in production
  # (or set XTURN_SERVER_IP and use certs/ under the app for local lab).
  certs: [
    certfile: "certs/server.crt",
    keyfile: "certs/server.key"
  ],
  cert_watch_interval_ms: 60_000

config :maru, Xirsys.API, http: [port: 8880]

if File.exists?("config/#{Mix.env()}.exs") do
  import_config "#{Mix.env()}.exs"
end

if File.exists?("config/runtime.exs") do
  import_config "runtime.exs"
end
