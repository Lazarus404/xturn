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

defmodule Xirsys.XTurn.Actions.HasRequestedTransport do
  @moduledoc """
  Guard that validates REQUESTED-TRANSPORT on **Allocate**.

  ## What problem this solves

  Allocate must declare whether the relay uses UDP or TCP. This step rejects
  missing, unsupported, or mismatched transport requests (for example TCP
  relay on a UDP socket) before any relay resources are opened.

  First step in the `@allocation` pipeline.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - REQUESTED-TRANSPORT (pt.6.2)
  * [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656) - TCP relay constraints
  """
  require Logger
  alias XSockets.Transport.{TCP, TLS}
  alias Xirsys.XTurn.Conn

  @udp_proto <<17, 0, 0, 0>>
  @tcp_proto <<6, 0, 0, 0>>

  @doc """
  Ensures REQUESTED-TRANSPORT is present and UDP/TCP is allowed on this socket.

  Passes conn through on success; returns conn with 400 or 442 error response
  when the attribute is missing, unsupported, or TCP is requested on a datagram socket.
  """
  def process(%Conn{decoded_message: %{attrs: attrs}, client_socket: client_socket} = conn) do
    with true <- Map.has_key?(attrs, :requested_transport),
         proto when proto in [@udp_proto, @tcp_proto] <- Map.get(attrs, :requested_transport),
         :ok <- tcp_control_allowed?(proto, client_socket) do
      conn
    else
      false ->
        Logger.error(
          "Request transport not provided from ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        Conn.response(conn, 400, "Bad Request")

      _ ->
        Logger.error(
          "Unsupported transport protocol requested from ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        Conn.response(conn, 442, "Unsupported Transport Protocol")
    end
  end

  # RFC 6062 / RFC 7350: TCP allocations only on TCP/TLS control (not UDP/DTLS).
  defp tcp_control_allowed?(@tcp_proto, %{transport: mod})
       when mod in [TCP, TLS],
       do: :ok

  defp tcp_control_allowed?(@tcp_proto, _client_socket), do: {:error, :unsupported}

  defp tcp_control_allowed?(_, _client_socket), do: :ok
end
