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

defmodule Xirsys.XTurn.Actions.ChannelData do
  @moduledoc """
  Pipeline action for TURN **ChannelData** messages.

  ## What problem this solves

  After ChannelBind, clients send media as compact ChannelData frames (not
  full STUN). This action looks up the bound peer and forwards the payload
  through the relay.

  Not a STUN request method; handled in the `@channeldata` chain when the
  message prefix indicates channel data rather than a STUN header.

  ## Internal

  Pipeline action only; also invoked from the media fast path via `DataPlane`.
  Not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - ChannelData (pt.11)
  """
  alias Xirsys.XTurn.DataPlane
  alias Xirsys.XTurn.Conn

  @doc """
  Forwards raw channel-data payload to the bound peer via `DataPlane`.

  Returns conn unchanged on forward or drop, `false` when no matching channel
  exists, or `false` on the TCP control socket.
  """
  def process(%Conn{is_control: true}), do: false

  def process(%Conn{message: message} = conn) do
    case DataPlane.forward_channel(message, meta(conn)) do
      :ok -> conn
      :not_found -> false
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
