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

defmodule Xirsys.XTurn.Actions.SendIndication do
  @moduledoc """
  Pipeline action for TURN **Send** indications.

  ## What problem this solves

  Before a channel is bound, the client sends application data to a peer using
  a **Send** indication (STUN-formatted, no response). This action forwards
  that payload through the relay to the permitted peer.

  Handled in the `@indication` chain; no STUN response is expected.

  ## Internal

  Pipeline action only; also invoked from the media fast path via `DataPlane`.
  Not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - Send indication (pt.9)
  """
  alias Xirsys.XTurn.DataPlane
  alias Xirsys.XTurn.Conn

  @doc """
  Forwards indication payload to the peer via `DataPlane`.

  Returns conn unchanged; skipped (`false`) on the TCP control socket.
  """
  def process(%Conn{is_control: true}), do: false

  def process(%Conn{message: message} = conn) do
    case DataPlane.forward_send(message, meta(conn)) do
      :ok -> conn
      :not_found -> conn
      :drop -> conn
    end
  end

  defp meta(%Conn{} = conn) do
    %{
      client_ip: conn.client_ip,
      client_port: conn.client_port,
      server_ip: conn.server_ip,
      server_port: conn.server_port,
      transport: conn.client_socket.transport,
      socket: conn.client_socket.socket,
      is_control: conn.is_control
    }
  end
end
