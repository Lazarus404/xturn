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

defmodule Xirsys.XTurn.Auth.AccessToken do
  @moduledoc """
  RFC 7635 third-party authorization access tokens.

  ## What problem this solves

  Some deployments let an authorization server mint temporary MAC keys instead
  of sharing user passwords with the TURN server. The ACCESS-TOKEN attribute
  carries an encrypted blob; this module mints and verifies those tokens
  (AES-256-GCM over a 20-byte MAC key, issue time, and lifetime) using the
  configured AEAD key and server name as additional authenticated data.

  Opt-in via `:third_party_auth` application env. Long-term credentials and
  MESSAGE-INTEGRITY (RFC 8489) remain the default path when disabled.

  ## RFCs

  - [RFC 7635](https://www.rfc-editor.org/rfc/rfc7635) (OAuth 2.0 third-party
    authorization for STUN/TURN, ACCESS-TOKEN attribute)
  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (MESSAGE-INTEGRITY with
    token-derived MAC key)
  """

  @mac_key_len 20
  @delta_seconds 5

  defp third_party_cfg do
    case Application.get_env(:xturn, :third_party_auth) do
      cfg when is_list(cfg) -> cfg
      _ -> []
    end
  end

  @doc "Returns `true` when `:third_party_auth` is enabled and a valid AEAD key is configured."
  def enabled?() do
    cfg = third_party_cfg()
    Keyword.get(cfg, :enabled, false) == true and is_binary(aead_key())
  end

  @doc "Returns the configured authorization-server URI, or `nil`."
  def as_uri() do
    Keyword.get(third_party_cfg(), :as_uri)
  end

  @doc "Returns the 32-byte AEAD key from config, or `nil` when missing or invalid."
  def aead_key() do
    case Keyword.get(third_party_cfg(), :aead_key) do
      key when is_binary(key) and byte_size(key) == 32 -> key
      _ -> nil
    end
  end

  @doc "Returns the configured server name used as GCM AAD, defaulting to `:realm`."
  def server_name() do
    case Keyword.get(third_party_cfg(), :server_name) do
      name when is_binary(name) and name != "" -> name
      _ -> Application.get_env(:xturn, :realm, "xirsys.com")
    end
  end

  @doc """
  Mints an encrypted access token for `mac_key` with `lifetime_seconds` validity.

  Uses the current system time as the issue timestamp. See `mint/5` to pin time
  for testing.

  ## Examples

      iex> key = :crypto.hash(:sha256, "doctest-aead-key")
      iex> server = "turn.example.com"
      iex> mac_key = :crypto.strong_rand_bytes(20)
      iex> token = Xirsys.XTurn.Auth.AccessToken.mint(mac_key, 60, key, server)
      iex> {:ok, ^mac_key} = Xirsys.XTurn.Auth.AccessToken.verify(token, key, server)
  """
  @spec mint(binary(), pos_integer(), binary(), binary()) :: binary()
  def mint(mac_key, lifetime_seconds, aead_key, server_name \\ server_name()) do
    mint(mac_key, lifetime_seconds, aead_key, server_name, System.system_time(:second))
  end

  @doc """
  Mints an encrypted access token using an explicit issue timestamp (Unix seconds).

  Prefer `mint/4` for production; this arity supports deterministic tests.
  """
  @spec mint(binary(), pos_integer(), binary(), binary(), integer()) :: binary()
  def mint(mac_key, lifetime_seconds, aead_key, server_name, timestamp_seconds)
      when is_binary(mac_key) and byte_size(mac_key) == @mac_key_len and is_integer(lifetime_seconds) and
             is_binary(aead_key) and byte_size(aead_key) == 32 and is_binary(server_name) and
             is_integer(timestamp_seconds) do
    timestamp = encode_timestamp(timestamp_seconds)
    plaintext = <<@mac_key_len::16, mac_key::binary, timestamp::binary, lifetime_seconds::32>>
    nonce = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, aead_key, nonce, plaintext, server_name, true)

    encrypted = ciphertext <> tag
    <<byte_size(nonce)::16, nonce::binary, encrypted::binary>>
  end

  @doc """
  Verifies `token` and returns `{:ok, mac_key}` on success.

  Uses the configured server name as GCM AAD. Returns `{:error, :invalid}` when
  decryption fails, the MAC key length is wrong, or the token is outside its lifetime.
  """
  @spec verify(binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def verify(token, aead_key) when is_binary(token) and is_binary(aead_key) do
    verify(token, aead_key, server_name())
  end

  @doc """
  Verifies `token` and returns `{:ok, mac_key}` using an explicit GCM AAD `server_name`.
  """
  @spec verify(binary(), binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def verify(token, aead_key, server_name)
      when is_binary(token) and is_binary(aead_key) and is_binary(server_name) do
    with <<nonce_len::16, rest::binary>> <- token,
         <<nonce::binary-size(^nonce_len), encrypted::binary>> <- rest,
         {:ok, plaintext} <- decrypt(encrypted, aead_key, nonce, server_name),
         <<key_len::16, mac_key::binary-size(key_len), ts::48, frac::16, lifetime::32>> <- plaintext,
         true <- key_len == @mac_key_len,
         true <- byte_size(mac_key) == @mac_key_len,
         true <- within_lifetime?(ts, frac, lifetime) do
      {:ok, mac_key}
    else
      _ -> {:error, :invalid}
    end
  end

  defp decrypt(encrypted, aead_key, nonce, aad) do
    tag_len = 16
    ciphertext_len = byte_size(encrypted) - tag_len

    if ciphertext_len < 0 do
      {:error, :invalid}
    else
      <<ciphertext::binary-size(^ciphertext_len), tag::binary-size(^tag_len)>> = encrypted

      case :crypto.crypto_one_time_aead(:aes_256_gcm, aead_key, nonce, ciphertext, aad, tag, false) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        _ -> {:error, :invalid}
      end
    end
  end

  defp encode_timestamp(seconds) when is_integer(seconds) and seconds >= 0 do
    <<seconds::48, 0::16>>
  end

  defp timestamp_to_seconds(seconds, frac) when is_integer(seconds) and is_integer(frac) do
    seconds + frac / 64_000
  end

  defp within_lifetime?(seconds, frac, lifetime) do
    rd_new = timestamp_to_seconds(System.system_time(:second), 0)
    ts = timestamp_to_seconds(seconds, frac)
    lifetime + @delta_seconds > abs(rd_new - ts)
  end
end
