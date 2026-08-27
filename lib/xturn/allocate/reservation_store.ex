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

defmodule Xirsys.XTurn.ReservationStore do
  @moduledoc """
  Short-lived holds for RFC 8656 RESERVATION-TOKEN relay ports.

  ## What problem this solves

  EVEN-PORT allocation can reserve the next odd port for a follow-up Allocate
  using RESERVATION-TOKEN. The server must keep that UDP socket bound but unused
  until the client claims it or the reservation expires.

  ## Internal note

  30-second TTL; expired reservations close the held socket.

  ## RFCs

  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (EVEN-PORT, RESERVATION-TOKEN)
  """

  @table :xturn_reservations
  @ttl_ms 30_000

  @doc "Creates the public reservation ETS table."
  def init, do: :ets.new(@table, [:named_table, :public, read_concurrency: true])

  @doc """
  Stores `{token, socket, port}` with a monotonic expiry timestamp.

  Returns `:ok`.
  """
  def reserve(token, socket, port) when is_binary(token) and byte_size(token) == 8 do
    expires = System.monotonic_time(:millisecond) + @ttl_ms
    :ets.insert(@table, {token, socket, port, expires})
    :ok
  end

  @doc """
  Atomically removes and returns a reservation.

  Returns `{:ok, socket, port}` when the token exists and has not expired,
  otherwise `:error` (expired reservations close their socket).
  """
  def claim(token) when is_binary(token) do
    case :ets.lookup(@table, token) do
      [{^token, socket, port, expires}] ->
        :ets.delete(@table, token)

        if System.monotonic_time(:millisecond) < expires do
          {:ok, socket, port}
        else
          :gen_udp.close(socket)
          :error
        end

      [] ->
        :error
    end
  end
end
