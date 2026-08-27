import Config

# Local self-signed PEMs for secure listeners (5349/TURNS). Production paths
# live in config.exs (/etc/xturn/certs/...); override here for mix run / iex.
config :xturn,
  certs: [
    certfile: "certs/server.crt",
    keyfile: "certs/server.key"
  ]
