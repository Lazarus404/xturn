import Config

certs? = File.exists?(Path.join(["certs", "server.crt"]))

turn_port =
  case System.get_env("XTURN_STUN_PORT") do
    nil -> 3478
    value -> String.to_integer(value)
  end

turns_port =
  case System.get_env("XTURN_TURNS_PORT") do
    nil -> 5349
    value -> String.to_integer(value)
  end

plain_entries = fn ip ->
  [{:udp, ip, turn_port}, {:tcp, ip, turn_port}]
end

secure_entries = fn ip ->
  if certs? do
    [{:udp, ip, turns_port, :secure}, {:tcp, ip, turns_port, :secure}]
  else
    []
  end
end

# Mix Config is not visible via Application.get_env/3 while this file is
# evaluated, so keep listen in a local and write it once.
listen_override = nil

# turnutils harness (xturn/test.sh): set XTURN_SERVER_IP to bind and advertise one address.
listen_override =
  if ip = System.get_env("XTURN_SERVER_IP") do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, tuple} ->
        ip_c = String.to_charlist(ip)
        listen = plain_entries.(ip_c) ++ secure_entries.(ip_c)

        config :xturn,
          server_ip: tuple,
          server_local_ip: tuple,
          certs: [
            certfile: "certs/server.crt",
            keyfile: "certs/server.key"
          ]

        listen

      {:error, _} ->
        raise "XTURN_SERVER_IP is not a valid IP address: #{inspect(ip)}"
    end
  else
    listen_override
  end

listen_override =
  if ip6 = System.get_env("XTURN_SERVER_IP6") do
    case :inet.parse_address(String.to_charlist(ip6)) do
      {:ok, tuple} ->
        ip6_c = String.to_charlist(ip6)

        config :xturn,
          server_ip6: tuple,
          server_local_ip6: tuple

        (listen_override || []) ++ plain_entries.(ip6_c) ++ secure_entries.(ip6_c)

      {:error, _} ->
        raise "XTURN_SERVER_IP6 is not a valid IP address: #{inspect(ip6)}"
    end
  else
    listen_override
  end

if listen_override do
  config :xturn, listen: listen_override
end

if System.get_env("XTURN_REST") == "1" do
  config :xturn,
    shared_secret: [
      enabled: true,
      secret: System.get_env("XTURN_REST_SECRET") || "turnutils-rest-secret",
      default_ttl_seconds: 300
    ]
end

if api_port = System.get_env("XTURN_API_PORT") do
  config :maru, Xirsys.API, http: [port: String.to_integer(api_port)]
end
