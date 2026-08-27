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

defmodule Xirsys.XTurn.ClientSocket do
  @moduledoc """
  Outbound send handle for data and STUN replies to the TURN client.

  ## What problem this solves

  Allocations and the data plane must send ChannelData, indications, and STUN
  responses back to the client over UDP, TCP, DTLS, or TLS. This struct bundles
  the transport module, underlying socket, and default client endpoint so send
  paths do not duplicate transport-specific logic.

  ## Internal note

  Created per message in workers and stored on allocations; not operator-facing.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (client-facing relay traffic)
  """

  @typedoc """
  Client-facing send handle.

  ## Fields

  - `:transport` - `XSockets.Transport.*` module for send/4
  - `:socket` - OS port, library conn socket, PID test stub, or `:fake`
  - `:client_ip` - default destination IP (may be nil for connected TCP)
  - `:client_port` - default destination port
  """
  @type t :: %__MODULE__{
          transport: module(),
          socket: term(),
          client_ip: :inet.ip_address() | nil,
          client_port: pos_integer() | nil
        }
  defstruct [:transport, :socket, :client_ip, :client_port]


  @doc """
  Builds a client send handle from transport module, socket, and client endpoint.
  """
  @spec new(module(), term(), :inet.ip_address() | nil, pos_integer() | nil) :: t()
  def new(transport, socket, client_ip, client_port) do
    %__MODULE__{
      transport: transport,
      socket: socket,
      client_ip: client_ip,
      client_port: client_port
    }
  end

  @doc "Builds a `%ClientSocket{}` from an `XSockets.Conn` and transport module."
  @spec from_library_conn(XSockets.Conn.t(), module()) :: t()
  def from_library_conn(%XSockets.Conn{} = conn, transport) do
    new(transport, conn.socket, conn.client_ip, conn.client_port)
  end

  @doc """
  Sends `data` to the client.

  Uses `dest_ip`/`dest_port` when provided, otherwise the stored client endpoint.
  PID and `:fake` sockets are handled for tests and worker relay paths.
  """
  @spec send(t(), iodata(), :inet.ip_address() | nil, :inet.port_number() | nil) ::
          :ok | {:error, term()}
  def send(%__MODULE__{} = client, data, dest_ip \\ nil, dest_port \\ nil) do
    cond do
      is_pid(client.socket) ->
        Kernel.send(client.socket, {:turn_client, data})
        :ok

      client.socket == :fake ->
        :ok

      true ->
        to =
          cond do
            dest_ip && dest_port -> {dest_ip, dest_port}
            client.client_ip -> {client.client_ip, client.client_port}
            true -> nil
          end

        client.transport.send(client.socket, data, to)
    end
  end
end
