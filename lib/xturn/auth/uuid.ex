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

defmodule Xirsys.XTurn.Auth.UUID do
  @moduledoc """
  Random identifiers and hex encoding for TURN credential challenges.

  ## What problem this solves

  Long-term STUN/TURN authentication needs unpredictable nonces and usernames
  on the wire. This module produces lowercase hex strings from cryptographically
  random bytes and time-prefixed nonce material without an external UUID library.

  Internal: called by `Auth.NonceStore` and `Auth.Client` during credential
  provisioning and 401 challenge issuance.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (long-term credentials,
    NONCE attribute, MESSAGE-INTEGRITY)
  - [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN long-term credential
    mechanism, legacy interop)
  """
  @vsn "0"

  @doc """
  Hex-encodes a binary, byte list, or empty list to lowercase ASCII char codes.

  ## Examples

      iex> Xirsys.XTurn.Auth.UUID.to_hex(<<0xAB, 0x0C>>)
      ~c"ab0c"

      iex> Xirsys.XTurn.Auth.UUID.to_hex([])
      []
  """
  def to_hex([]),
    do: []

  def to_hex(bin) when is_binary(bin),
    do: to_hex(:erlang.binary_to_list(bin))

  def to_hex([h | t]),
    do: [to_digit(div(h, 16)), to_digit(rem(h, 16)) | to_hex(t)]

  @doc """
  Maps a nibble (`0`-`15`) to its lowercase hex ASCII code.

  ## Parameters

    * `n` - integer from `0` to `15`

  ## Examples

      iex> Xirsys.XTurn.Auth.UUID.to_digit(9)
      57

      iex> Xirsys.XTurn.Auth.UUID.to_digit(10)
      97
  """
  def to_digit(n) when n < 10 do
    [t] = ~c"0"
    t + n
  end

  def to_digit(n) do
    [t] = ~c"a"
    t + n - 10
  end

  @doc """
  Returns 32 lowercase hex characters from 16 cryptographically random bytes.
  """
  def random(),
    do: to_hex(:crypto.strong_rand_bytes(16))

  @doc """
  Returns a time-prefixed nonce binary for credential challenges.

  The prefix is 14 uppercase hex digits of microseconds since the Unix epoch,
  followed by 18 lowercase hex characters from 9 random bytes.
  """
  def utc_random() do
    now = {_, _, micro} = :erlang.timestamp()
    nowish = :calendar.now_to_universal_time(now)
    nowsecs = :calendar.datetime_to_gregorian_seconds(nowish)
    then = :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})
    prefix = :io_lib.format("~14.16.0b", [(nowsecs - then) * 1_000_000 + micro])
    :erlang.list_to_binary(prefix ++ to_hex(:crypto.strong_rand_bytes(9)))
  end
end
