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

defmodule Xirsys.XTurn.Auth.SharedSecret do
  @moduledoc """
  Stateless TURN REST API credentials (coturn-compatible shared secret).

  ## What problem this solves

  Signaling servers and Web backends need to mint time-limited TURN username/
  password pairs without storing per-user secrets on the TURN server. The TURN
  REST API pattern embeds expiry in the username and derives the password from
  a shared HMAC key, matching coturn's `use-auth-secret` deployment model.

  Usernames are `"<expiry-unix>:<user-id>"`; passwords are
  `Base64(HMAC-SHA1(secret, username))`. Verification recomputes the HMAC and
  rejects expired usernames before Allocate proceeds.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (long-term credentials,
    MESSAGE-INTEGRITY key derivation from the REST password)
  - TURN REST shared-secret credentials (coturn-compatible; widely deployed
    alongside [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) TURN)
  """

  @doc """
  Generates a time-limited REST username/password pair for `user_id`.

  The username embeds the Unix expiry timestamp; the password is the
  Base64-encoded HMAC-SHA1 of the username under `secret`.
  """
  @spec generate(String.t(), pos_integer(), binary()) :: {String.t(), String.t()}
  def generate(user_id, ttl_seconds, secret) when is_binary(secret) and ttl_seconds > 0 do
    expiry = System.system_time(:second) + ttl_seconds
    username = "#{expiry}:#{user_id}"
    password = hmac_password(username, secret)
    {username, password}
  end

  @doc """
  Validates a REST username and returns the expected password on success.

  Returns `:expired` when the embedded timestamp is in the past, or `:error`
  when the username format is invalid.

  ## Examples

      iex> secret = "test-secret"
      iex> {username, password} = Xirsys.XTurn.Auth.SharedSecret.generate("alice", 3600, secret)
      iex> {:ok, ^password} = Xirsys.XTurn.Auth.SharedSecret.verify_username(username, secret)

      iex> past = System.system_time(:second) - 10
      iex> Xirsys.XTurn.Auth.SharedSecret.verify_username(to_string(past) <> ":bob", "secret")
      :expired
  """
  @spec verify_username(String.t(), binary()) :: {:ok, String.t()} | :expired | :error
  def verify_username(username, secret) when is_binary(username) and is_binary(secret) do
    with [expiry_str, _user_id] <- String.split(username, ":", parts: 2),
         {expiry, ""} <- Integer.parse(expiry_str) do
      now = System.system_time(:second)

      cond do
        expiry <= now -> :expired
        true -> {:ok, hmac_password(username, secret)}
      end
    else
      _ -> :error
    end
  end

  @doc """
  Returns `true` when `username` matches the `<expiry>:<user-id>` REST format.

  ## Examples

      iex> Xirsys.XTurn.Auth.SharedSecret.rest_username?("1700000000:alice")
      true

      iex> Xirsys.XTurn.Auth.SharedSecret.rest_username?("alice")
      false
  """
  @spec rest_username?(String.t()) :: boolean()
  def rest_username?(username) when is_binary(username) do
    case String.split(username, ":", parts: 2) do
      [expiry_str, _user_id] -> match?({_, ""}, Integer.parse(expiry_str))
      _ -> false
    end
  end

  defp hmac_password(username, secret) do
    :crypto.mac(:hmac, :sha, secret, username)
    |> Base.encode64()
  end
end
