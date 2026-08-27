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

defmodule Xirsys.XTurn.Actions.Connect do
  @moduledoc """
  Pipeline action for TURN **Connect** requests.

  ## What problem this solves

  For TCP relay allocations, the client asks the server to open an outbound TCP
  connection to a peer. **Connect** performs that dial and returns a
  CONNECTION-ID the client uses with **ConnectionBind** to splice data paths.

  Runs in the `@connect` chain after `Authenticates`; TCP allocations only.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062) - Connect (pt.4)
  """
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.PeerFilter
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn

  @doc """
  Opens an outbound TCP connection to XOR-PEER-ADDRESS on the allocation.

  Returns conn with success and CONNECTION-ID, or 400/403/437/446/447 on error.
  """
  def process(%Conn{decoded_message: %{attrs: attrs}} = conn) do
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))

    case Store.lookup(tuple5) do
      {:ok, [client, _, _, _]} ->
        if AllocateClient.requested_transport(client) == :tcp do
          do_connect(conn, client, attrs)
        else
          Conn.response(conn, 437, "Allocation Mismatch")
        end

      {:error, :not_found} ->
        Conn.response(conn, 437, "Allocation Mismatch")
    end
  end

  defp do_connect(conn, client, attrs) do
    families = AllocateClient.active_families(client)

    case Map.get(attrs, :xor_peer_address) do
      {_, _} = peer ->
        cond do
          PeerFilter.forbidden?(peer, conn.client_ip, families) ->
            Conn.response(conn, 403, "Forbidden")

          true ->
            case AllocateClient.tcp_connect(client, peer) do
              {:ok, connection_id} ->
                Conn.response(conn, :success, %{connection_id: connection_id})

              {:error, :timeout} ->
                Conn.response(conn, 447, "Connection Timeout or Failure")

              {:error, :exists} ->
                Conn.response(conn, 446, "Connection Already Exists")

              {:error, _} ->
                Conn.response(conn, 447, "Connection Timeout or Failure")
            end
        end

      _ ->
        Conn.response(conn, 400, "Bad Request")
    end
  end
end
