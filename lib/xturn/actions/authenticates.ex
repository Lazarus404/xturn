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
### DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
### ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###
### ----------------------------------------------------------------------

defmodule Xirsys.XTurn.Actions.Authenticates do
  @moduledoc """
  Shared pipeline gate for STUN/TURN methods that require credentials.

  ## What problem this solves

  TURN must verify that the client holds valid credentials before creating or
  using an allocation. This action checks nonce freshness, username/password
  (or access token), password algorithms, and MESSAGE-INTEGRITY on each
  protected request.

  Runs before Allocate, Refresh, ChannelBind, CreatePerm, Connect, and
  ConnectionBind in their respective pipeline chains.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) - STUN (long-term credentials, MESSAGE-INTEGRITY-SHA256)
  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - STUN (MESSAGE-INTEGRITY, nonce)
  * [RFC 7635](https://datatracker.ietf.org/doc/html/rfc7635) - STUN extension for OAuth (access token path)
  """
  require Logger
  alias Xirsys.XTurn.Auth.Client, as: AuthClient
  alias Xirsys.XTurn.Auth.{AccessToken, NonceStore, SharedSecret}
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn
  alias XMediaLib.Stun

  @doc """
  Validates nonce, credentials, and message integrity for the current request.

  Passes conn through unchanged when auth is disabled or not required; on success
  updates `decoded_message` with verified attrs and key; on failure sets an error
  response (400, 401, 438, 437, or 441).
  """
  def process(
        %Conn{force_auth: force_auth, message: message, decoded_message: %{attrs: attrs, method: method}} =
          conn
      ) do
    authenticate? = auth_required?() or force_auth
    client_key = {conn.client_ip, conn.client_port}

    cond do
      not authenticate? ->
        conn

      allocation_bound?(method) ->
        process_allocation_auth(conn, client_key)

      access_token_allocate?(method, attrs) ->
        process_access_token_allocate(conn, message, attrs, client_key)

      has_integrity?(attrs) and missing_credentials?(attrs) ->
        Conn.response(conn, 400, "Bad Request")

      true ->
        with username when is_binary(username) <- resolve_username(attrs),
             :ok <- check_password_algorithms(attrs),
             :ok <- check_nonce(method, attrs, client_key),
             turn_dec when is_map(turn_dec) <-
               process_integrity(message, username, attrs) do
          %Conn{conn | decoded_message: turn_dec}
        else
          {:error, :bad_request} ->
            Conn.response(conn, 400, "Bad Request")

          :stale ->
            Conn.response(conn, 438, "Stale Nonce", NonceStore.issue(client_key))

          :mismatch ->
            Conn.response(conn, 438, "Stale Nonce", NonceStore.issue(client_key))

          _ ->
            Conn.response(conn, 401, "Unauthorized")
        end
    end
  end

  defp allocation_bound?(method),
    do: method in [:refresh, :createperm, :channelbind, :connect]

  defp access_token_allocate?(:allocate, attrs),
    do: AccessToken.enabled?() and Map.has_key?(attrs, :access_token)

  defp access_token_allocate?(_, _), do: false

  defp process_access_token_allocate(%Conn{} = conn, msg, attrs, _client_key) do
    token = Map.get(attrs, :access_token)

    with {:ok, mac_key} <- AccessToken.verify(token, AccessToken.aead_key()),
         {:ok, turn} <- Stun.decode(msg, mac_key) do
      attrs = Map.put(turn.attrs, :username, "access-token")
      turn = struct(turn, %{key: mac_key, attrs: attrs})
      %Conn{conn | decoded_message: turn}
    else
      _ ->
        Conn.response(conn, 401, "Unauthorized")
    end
  end

  defp process_allocation_auth(conn, client_key) do
    attrs = conn.decoded_message.attrs
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))

    with {:ok, [client, _, _, _]} <- Store.lookup(tuple5),
         {alloc_user, stored_key} <- AllocateClient.get_credentials(client) do
      cond do
        has_integrity?(attrs) and missing_credentials?(attrs) ->
          Conn.response(conn, 400, "Bad Request")

        wrong_user?(alloc_user, attrs) ->
          Conn.response(conn, 441, "Wrong Credentials")

        true ->
          with :ok <- check_password_algorithms(attrs),
               :ok <- check_nonce(conn.decoded_message.method, attrs, client_key),
               turn_dec when is_map(turn_dec) <- decode_with_stored_key(conn.message, stored_key) do
            %Conn{conn | decoded_message: turn_dec}
          else
            {:error, :bad_request} ->
              Conn.response(conn, 400, "Bad Request")

            :stale ->
              Conn.response(conn, 438, "Stale Nonce", NonceStore.issue(client_key))

            :mismatch ->
              Conn.response(conn, 438, "Stale Nonce", NonceStore.issue(client_key))

            _ ->
              Conn.response(conn, 401, "Unauthorized")
          end
      end
    else
      {:error, :not_found} ->
        Conn.response(conn, 437, "Allocation Mismatch")

      _ ->
        Conn.response(conn, 401, "Unauthorized")
    end
  end

  defp wrong_user?(alloc_user, attrs) when is_binary(alloc_user) and is_map(attrs) do
    cond do
      Map.has_key?(attrs, :userhash) ->
        expected = userhash(alloc_user)
        Map.get(attrs, :userhash) != expected

      Map.has_key?(attrs, :username) ->
        alloc_user != Map.get(attrs, :username)

      true ->
        false
    end
  end

  defp wrong_user?(_, _), do: false

  defp resolve_username(attrs) do
    cond do
      Map.has_key?(attrs, :username) ->
        Map.get(attrs, :username)

      Map.has_key?(attrs, :userhash) ->
        case AuthClient.get_details_by_hash(Map.get(attrs, :userhash)) do
          {:ok, username, _, _, _} -> username
          _ -> nil
        end

      true ->
        nil
    end
  end

  defp userhash(username) do
    :crypto.hash(:sha256, Stun.opaque_string(username) <> ":" <> Stun.opaque_string(realm()))
  end

  defp decode_with_stored_key(_msg, key) when not is_binary(key), do: false

  defp decode_with_stored_key(msg, key) do
    case Stun.decode(msg, key) do
      {:ok, turn} -> turn
      _ -> false
    end
  end

  defp has_integrity?(attrs) do
    Map.has_key?(attrs, :message_integrity) or Map.has_key?(attrs, :message_integrity_sha256)
  end

  defp missing_credentials?(attrs) do
    (not Map.has_key?(attrs, :username) and not Map.has_key?(attrs, :userhash)) or
      not Map.has_key?(attrs, :realm) or
      not is_binary(Map.get(attrs, :nonce)) or Map.get(attrs, :nonce) == ""
  end

  defp check_nonce(:connection_bind, attrs, {ip, _port}) do
    NonceStore.validate_for_ip(ip, Map.get(attrs, :nonce))
  end

  defp check_nonce(_method, attrs, client_key) do
    NonceStore.validate(client_key, Map.get(attrs, :nonce))
  end

  defp check_password_algorithms(attrs) do
    case Map.get(attrs, :nonce) do
      nonce when is_binary(nonce) ->
        if password_algorithms_cookie?(nonce) do
          check_password_algorithms_echo(attrs)
        else
          :ok
        end

      _ ->
        :ok
    end
  end

  defp check_password_algorithms_echo(attrs) do
    palgs = Map.get(attrs, :password_algorithms)
    palg = Map.get(attrs, :password_algorithm)

    cond do
      is_nil(palgs) and is_nil(palg) -> :ok
      palgs == NonceStore.password_algorithms() and is_binary(palg) and
          algorithm_in_list?(palg, palgs) ->
        :ok

      true ->
        {:error, :bad_request}
    end
  end

  defp password_algorithms_cookie?(<<"obMatJos2", _::binary-size(4), _::binary>> = nonce) do
    <<_::binary-size(9), flags_b64::binary-size(4), _::binary>> = nonce

    case Base.decode64(flags_b64) do
      {:ok, <<1::1, _::23>>} -> true
      _ -> false
    end
  end

  defp password_algorithms_cookie?(_), do: false

  defp algorithm_in_list?(palg, palgs) when is_binary(palg) and is_binary(palgs) do
    <<alg::16, _::binary>> = palg
    algorithm_in_list_palgs?(palgs, alg)
  end

  defp algorithm_in_list_palgs?(<<alg::16, plen::16, rest::binary>>, wanted) do
    if alg == wanted do
      true
    else
      pad = rem(4 - rem(plen, 4), 4)
      <<_params::binary-size(^plen), _pad::binary-size(^pad), tail::binary>> = rest
      algorithm_in_list_palgs?(tail, wanted)
    end
  end

  defp algorithm_in_list_palgs?(_, _), do: false

  defp auth_required?() do
    case Application.get_env(:xturn, :authentication) do
      %{required: required} -> required
      _ -> true
    end
  end

  defp realm(), do: Application.get_env(:xturn, :realm)

  defp process_integrity(msg, username, attrs) do
    Logger.info("Checking USERNAME #{inspect(username)}")

    with {:ok, pw, ns, peer_id} <- lookup_password(username),
         key_material <-
           username <>
             ":" <> Stun.opaque_string(realm()) <>
             ":" <> Stun.opaque_string(pw),
         key <- derive_key(key_material, Map.get(attrs, :password_algorithm)),
         {:ok, turn} <- Stun.decode(msg, key) do
      attrs = Map.put(turn.attrs, :username, username)
      struct(turn, %{key: key, ns: ns, peer_id: peer_id, attrs: attrs})
    else
      e ->
        Logger.info("Integrity process failed: #{inspect(e)}")
        false
    end
  end

  defp derive_key(material, <<2::16, _::binary>>), do: :crypto.hash(:sha256, material)
  defp derive_key(material, _), do: :crypto.hash(:md5, material)

  defp lookup_password(username) do
    cond do
      shared_secret_enabled?() and SharedSecret.rest_username?(username) ->
        case SharedSecret.verify_username(username, shared_secret()) do
          {:ok, pw} -> {:ok, pw, nil, nil}
          _ -> :error
        end

      true ->
        case AuthClient.get_details(username) do
          {:ok, pass, ns, peer_id} -> {:ok, pass, ns, peer_id}
          _ -> :error
        end
    end
  end

  defp shared_secret_enabled?() do
    cfg = Application.get_env(:xturn, :shared_secret, [])

    Keyword.get(cfg, :enabled) == true and
      is_binary(Keyword.get(cfg, :secret)) and Keyword.get(cfg, :secret) != ""
  end

  defp shared_secret() do
    Application.get_env(:xturn, :shared_secret, [])
    |> Keyword.get(:secret)
  end
end
