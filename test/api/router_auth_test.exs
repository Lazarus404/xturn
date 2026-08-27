defmodule Xirsys.API.Router.AuthTest do
  use ExUnit.Case, async: false

  import Plug.Test

  @opts Xirsys.API.init([])

  test "GET /auth/rest returns 503 when shared secret is disabled" do
    saved = Application.get_env(:xturn, :shared_secret)
    Application.put_env(:xturn, :shared_secret, enabled: false, secret: nil)
    on_exit(fn -> Application.put_env(:xturn, :shared_secret, saved) end)

    conn = conn(:get, "/auth/rest") |> Xirsys.API.call(@opts)
    assert conn.status == 503
    assert %{"status" => "error"} = Jason.decode!(conn.resp_body)
  end

  test "GET /auth/rest returns credentials when shared secret is enabled" do
    saved_secret = Application.get_env(:xturn, :shared_secret)
    saved_ip = Application.get_env(:xturn, :server_ip)
    saved_certs = Application.get_env(:xturn, :certs)

    Application.put_env(:xturn, :shared_secret,
      enabled: true,
      secret: "router-test-secret",
      default_ttl_seconds: 120
    )

    Application.put_env(:xturn, :server_ip, {203, 0, 113, 1})
    Application.put_env(:xturn, :certs, certfile: "certs/missing.crt", keyfile: "certs/missing.key")

    on_exit(fn ->
      Application.put_env(:xturn, :shared_secret, saved_secret)
      Application.put_env(:xturn, :server_ip, saved_ip)
      Application.put_env(:xturn, :certs, saved_certs)
    end)

    conn = conn(:get, "/auth/rest?username=alice") |> Xirsys.API.call(@opts)
    assert conn.status == 200

    body = Jason.decode!(conn.resp_body)
    assert body["status"] == "ok"
    assert is_binary(body["username"])
    assert is_binary(body["password"])
    assert body["ttl"] == 120

    uris = body["uris"]
    assert is_list(uris)
    assert "turn:203.0.113.1:3478?transport=udp" in uris
    assert "turn:203.0.113.1:3478?transport=tcp" in uris
    refute Enum.any?(uris, &String.starts_with?(&1, "turns:"))
  end

  test "GET /auth/rest uris include turns when certs exist" do
    saved_secret = Application.get_env(:xturn, :shared_secret)
    saved_ip = Application.get_env(:xturn, :server_ip)
    saved_ip6 = Application.get_env(:xturn, :server_ip6)
    saved_certs = Application.get_env(:xturn, :certs)

    cert = Path.join(System.tmp_dir!(), "xturn-rest-test-#{:erlang.unique_integer([:positive])}.crt")
    File.write!(cert, "fake")

    Application.put_env(:xturn, :shared_secret,
      enabled: true,
      secret: "router-test-secret",
      default_ttl_seconds: 120
    )

    Application.put_env(:xturn, :server_ip, {203, 0, 113, 2})
    Application.put_env(:xturn, :server_ip6, {0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1})
    Application.put_env(:xturn, :certs, certfile: cert, keyfile: cert)

    on_exit(fn ->
      File.rm(cert)
      Application.put_env(:xturn, :shared_secret, saved_secret)
      Application.put_env(:xturn, :server_ip, saved_ip)
      Application.put_env(:xturn, :server_ip6, saved_ip6)
      Application.put_env(:xturn, :certs, saved_certs)
    end)

    conn = conn(:get, "/auth/rest?username=alice") |> Xirsys.API.call(@opts)
    body = Jason.decode!(conn.resp_body)
    uris = body["uris"]

    assert "turn:[2001:db8::1]:3478?transport=udp" in uris
    assert "turns:203.0.113.2:5349?transport=tcp" in uris
  end
end
