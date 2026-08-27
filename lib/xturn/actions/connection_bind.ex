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

defmodule Xirsys.XTurn.Actions.ConnectionBind do
  @moduledoc """
  Pipeline action for TURN **ConnectionBind** requests.

  ## What problem this solves

  After **Connect** succeeds, the client opens a second TCP connection and sends
  **ConnectionBind** with the CONNECTION-ID. This action attaches that client
  data socket to the pending peer connection so bytes flow end-to-end.

  Runs in the `@connection_bind` chain after `Authenticates`.

  ## Internal

  Pipeline action only; also handled inline by `Handlers.StunTurn` on spliced
  TCP sockets. Not part of the public application API.

  ## RFCs

  * [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062) - ConnectionBind (pt.4.2)
  """

  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.Allocate.TcpRegistry
  alias Xirsys.XTurn.Conn

  @doc """
  Binds the client data connection to a pending CONNECTION-ID.

  On success returns conn with a success response and `splice_peer` set for
  socket splicing; otherwise returns conn with a 400 error response.
  """
  def process(%Conn{decoded_message: %{attrs: attrs}, client_socket: client_socket} = conn) do
    case Map.get(attrs, :connection_id) do
      connection_id when is_binary(connection_id) and byte_size(connection_id) == 4 ->
        case TcpRegistry.lookup_alloc(connection_id) do
          {:ok, alloc_pid} ->
            case AllocateClient.connection_bind(alloc_pid, connection_id, client_socket, self()) do
              {:ok, peer_socket} ->
                %Conn{Conn.response(conn, :success) | splice_peer: peer_socket}

              {:error, _} ->
                Conn.response(conn, 400, "Bad Request")
            end

          :error ->
            Conn.response(conn, 400, "Bad Request")
        end

      _ ->
        Conn.response(conn, 400, "Bad Request")
    end
  end
end
