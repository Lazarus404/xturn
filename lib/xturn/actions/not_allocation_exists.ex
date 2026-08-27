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

defmodule Xirsys.XTurn.Actions.NotAllocationExists do
  @moduledoc """
  Guard that rejects duplicate **Allocate** on the same client 5-tuple.

  ## What problem this solves

  Only one allocation may exist per client 5-tuple. If the client retries the
  same Allocate transaction, this step replays the success response; if a
  different transaction arrives while an allocation is active, it returns 437.

  Second step in the `@allocation` pipeline, before `Authenticates`.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - one allocation per 5-tuple (pt.6.2)
  """
  require Logger
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn

  @doc """
  If an allocation exists for this 5-tuple, replays success for the same
  transaction ID or responds 437 and halts the pipeline.

  Otherwise passes conn through unchanged for a new allocation.
  """
  def process(%Conn{decoded_message: %{attrs: attrs, transactionid: tid}} = conn) do
    proto = Map.get(attrs, :requested_transport)
    tuple5 = Tuple5.to_map(Tuple5.create(conn, proto))

    case Store.lookup(tuple5) do
      {:ok, [client, {_ip, _port}, _, _]} ->
        if AllocateClient.get_id(client) == tid do
          Logger.info(
            "Idempotent Allocate retransmit from ip:#{inspect(conn.client_ip)}, port:#{
              inspect(conn.client_port)
            }"
          )

          relays = AllocateClient.get_relay_addresses(client)

          xor_relayed =
            case relays do
              [one] -> one
              many -> many
            end

          nattrs = %{
            xor_mapped_address: {conn.client_ip, conn.client_port},
            xor_relayed_address: xor_relayed,
            lifetime: lifetime_tlv(AllocateClient.get_lifetime(client))
          }

          conn |> Conn.response(:success, nattrs) |> Conn.halt()
        else
          Logger.info(
            "Allocation mismatch from ip:#{inspect(conn.client_ip)}, port:#{
              inspect(conn.client_port)
            }"
          )

          conn |> Conn.response(437, "Allocation Mismatch") |> Conn.halt()
        end

      _ ->
        conn
    end
  end

  defp lifetime_tlv(seconds) when is_integer(seconds), do: <<seconds::32>>
end
