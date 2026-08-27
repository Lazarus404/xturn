### ----------------------------------------------------------------------
###
### Copyright (c) 2013 - 2026 Jahred Love and Xirsys LLC <experts@xirsys.com>
###
### All rights reserved.
###
### Redistribution and use in source and binary forms, with or without modification,
### are permitted provided that the following conditions are met:
###
### * Redistributions of source code must retain the above copyright notice, this
### list of conditions and the following disclaimer.
### * Redistributions in binary form must reproduce the above copyright notice,
### this list of conditions and the following disclaimer in the documentation
### and/or other materials provided with the distribution.
### * Neither the name of the authors nor the names of its contributors
### may be used to endorse or promote products derived from this software
### without specific prior written permission.
###
### THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ''AS IS'' AND ANY
### EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
### WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
### DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
### ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###
### ----------------------------------------------------------------------

defmodule Xirsys.API.Router.Auth do
  @moduledoc """
  Operator REST routes under `/auth` for credential management.

  ## What problem this solves

  WebRTC signaling backends and operators need to create long-term TURN
  credentials and mint coturn-compatible REST shared-secret username/password
  pairs without custom tooling. `POST /auth` adds or generates users in
  `Auth.Client`; `GET /auth/rest` returns TTL credentials when shared-secret
  auth is enabled (503 when disabled).

  Responses include suggested `turn:` / `turns:` URIs derived from server config.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (long-term credentials,
    MESSAGE-INTEGRITY)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN URIs returned by
    REST minting)
  - TURN REST shared-secret credentials (coturn-compatible TTL usernames)
  """
  use Maru.Router

  alias Xirsys.XTurn.ListenConfig

  namespace :auth do
    desc("Adds a user to the user list")

    post do
      p = conn.params

      if missing_credentials?(p) do
        {:ok, u, pass} =
          Xirsys.XTurn.Auth.Client.create_user(param(p, :namespace) || "", param(p, :peer_id) || "")

        json(conn, %{status: :ok, username: u, password: pass})
      else
        {:ok, u, pass} =
          Xirsys.XTurn.Auth.Client.add_user(
            param(p, :username),
            param(p, :password),
            param(p, :namespace) || "",
            param(p, :peer_id) || ""
          )

        json(conn, %{status: :ok, username: u, password: pass})
      end
    end

    desc("Mint TURN REST API credentials (shared-secret / TTL)")

    get "rest" do
      case shared_secret_config() do
        {:ok, secret, default_ttl} ->
          ttl = parse_ttl(param(conn.params, :ttl), default_ttl)
          user_id = param(conn.params, :username) || "test-user"
          {username, password} = Xirsys.XTurn.Auth.SharedSecret.generate(user_id, ttl, secret)

          json(conn, %{
            status: :ok,
            username: username,
            password: password,
            ttl: ttl,
            uris: rest_uris()
          })

        {:error, :disabled} ->
          conn
          |> put_status(503)
          |> json(%{status: :error, message: "shared-secret authentication is not enabled"})
      end
    end
  end

  defp shared_secret_config do
    cfg = Application.get_env(:xturn, :shared_secret, [])

    if Keyword.get(cfg, :enabled) == true and is_binary(Keyword.get(cfg, :secret)) and
         Keyword.get(cfg, :secret) != "" do
      {:ok, Keyword.get(cfg, :secret), Keyword.get(cfg, :default_ttl_seconds, 86_400)}
    else
      {:error, :disabled}
    end
  end

  defp missing_credentials?(params) do
    blank?(param(params, :username)) or blank?(param(params, :password))
  end

  defp param(params, key) when is_map(params) do
    Map.get(params, key) || Map.get(params, to_string(key))
  end

  defp parse_ttl(n, _default) when is_integer(n) and n > 0, do: n

  defp parse_ttl(s, default) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} when n > 0 -> n
      _ -> default
    end
  end

  defp parse_ttl(_, default), do: default

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(_), do: false

  defp rest_uris do
    secure? = ListenConfig.certs_available?()

    for ip <- rest_server_ips(),
        {scheme, port, transport} <- rest_uri_variants(secure?) do
      "#{scheme}:#{format_rest_host(ip)}:#{port}?transport=#{transport}"
    end
  end

  defp rest_server_ips do
    []
    |> maybe_add_ip(Application.get_env(:xturn, :server_ip))
    |> maybe_add_ip(Application.get_env(:xturn, :server_ip6))
  end

  defp maybe_add_ip(ips, ip) when is_tuple(ip), do: ips ++ [ip]
  defp maybe_add_ip(ips, _), do: ips

  defp rest_uri_variants(true) do
    turn_port = ListenConfig.turn_port()
    turns_port = ListenConfig.turns_port()

    [
      {"turn", turn_port, "udp"},
      {"turn", turn_port, "tcp"},
      {"turns", turns_port, "tcp"}
    ]
  end

  defp rest_uri_variants(false) do
    turn_port = ListenConfig.turn_port()

    [
      {"turn", turn_port, "udp"},
      {"turn", turn_port, "tcp"}
    ]
  end

  defp format_rest_host({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_rest_host({_, _, _, _, _, _, _, _} = ip) do
    ip
    |> :inet.ntoa()
    |> to_string()
    |> String.downcase()
    |> then(&"[#{&1}]")
  end
end
