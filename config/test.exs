import Config

config :xturn, listen: []

# Loopback tests CreatePermission to 127.0.0.1 from 127.0.0.1. That is
# client-self unless the advertised TURN IP is loopback (hairpin exception).
config :xturn, server_ip: {127, 0, 0, 1}

# Tests assume unauthenticated allocation is permitted by default; pin this
# explicitly so it doesn't silently depend on whatever config.exs currently has
# set for manual/live debugging (e.g. authentication: %{required: true}).
config :xturn, authentication: %{required: false}

config :xturn,
  nonce_max_age_ms: 3_600_000,
  shared_secret: [
    enabled: false,
    secret: "test-shared-secret",
    default_ttl_seconds: 86_400
  ]

config :xturn,
  udp_listen_shards: 1,
  packet_log_enabled: false,
  client_worker_pool_size: 2

# Rate limiting is per client IP, and the suite drives many requests from a
# handful of loopback addresses, so leave it off by default and enable it
# explicitly in the tests that exercise it.
config :xturn, rate_limit_enabled: false

config :xturn,
  certs: [
    certfile: "certs/server.crt",
    keyfile: "certs/server.key"
  ],
  cert_watch_interval_ms: 60_000

config :logger, level: :warning
