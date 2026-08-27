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

defmodule Xirsys.XTurn.Handlers.StunTurn do
  @moduledoc """
  Socket handler that multiplexes TURN control and media on one connection.

  ## What problem this solves

  Clients send STUN/TURN control messages and high-rate media (ChannelData,
  Send) on the same socket. This handler classifies each complete frame and
  routes control to worker processes while forwarding media on a fast path that
  avoids GenServer bottlenecks. Only STUN requests count toward the per-IP rate
  limit so relay traffic does not stall control.

  ## Internal

  Registered as the `:handler` tier in `SocketPipeline`; not called by
  application code directly.

  ## RFCs

  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - STUN message classes (request vs indication)
  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - ChannelData and Send on client socket (pt.11)
  * [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062) - ConnectionBind on TCP data connection
  """
  @behaviour XSockets.Handler

  import Bitwise

  require Logger

  alias XSockets.Config
  alias XSockets.Conn, as: SockConn
  alias Xirsys.XTurn.Allocate.{Store, TcpRegistry}
  alias Xirsys.XTurn.{ClientSocket, ClientWorker.Pool, Conn, DataPlane, PacketLog, Pipeline, Tuple5}

  # STUN message-type class bits (RFC 5389, Section 6). A request has both
  # class bits clear; indications, success responses and error responses each
  # set at least one.
  @class_mask 0x0110
  @class_request 0x0000

  @doc """
  Classifies and routes one complete frame from the client socket.

  Media (ChannelData, Send) is forwarded via `DataPlane`; control STUN is
  dispatched to the client worker pool. ConnectionBind on a spliced TCP socket
  is handled inline through `Pipeline`. Returns `{:ok, nil}` - replies are sent
  asynchronously by workers or the fast path.
  """
  @impl true
  def handle_packet(frame, _meta, %SockConn{assigns: assigns, socket: socket} = sock_conn, _state) do
    transport = Map.fetch!(assigns, :transport)

    cond do
      TcpRegistry.spliced?(socket) ->
        {:ok, nil}

      throttled?(frame, sock_conn.client_ip) ->
        Logger.debug(
          "rate limited control-plane request from #{inspect(sock_conn.client_ip)}:#{inspect(sock_conn.client_port)}"
        )

        {:ok, nil}

      true ->
        if connection_bind_request?(frame) do
          process_connection_bind(frame, sock_conn, transport)
        else
          case DataPlane.classify(frame) do
            {:channel, _, _} = classified ->
              DataPlane.forward_channel(classified, packet_meta(sock_conn, transport, true))

            {:send, _, _} = classified ->
              DataPlane.forward_send(classified, packet_meta(sock_conn, transport, true))

            :control ->
              Pool.dispatch(frame, packet_meta(sock_conn, transport, false))

            :ignore ->
              :ok
          end
        end

        {:ok, nil}
    end
  end

  # Only STUN requests are budgeted. Relayed data (ChannelData, and the
  # Send/Data indications that carry media before a channel is bound) runs at
  # hundreds of packets per second, so counting it against a request budget
  # stalls media within seconds.
  defp throttled?(_frame, nil), do: false

  defp throttled?(<<0::2, type::14, _rest::binary>>, client_ip) do
    if (type &&& @class_mask) == @class_request do
      Config.check_rate_limit(client_ip) == {:error, :rate_limited}
    else
      false
    end
  end

  defp throttled?(_frame, _client_ip), do: false

  defp connection_bind_request?(<<0::2, 11::14, _::binary>>), do: true
  defp connection_bind_request?(_), do: false

  defp packet_meta(sock_conn, transport, check_control) do
    %{
      client_ip: sock_conn.client_ip,
      client_port: sock_conn.client_port,
      server_ip: sock_conn.server_ip,
      server_port: sock_conn.server_port,
      transport: transport,
      socket: sock_conn.socket,
      is_control: check_control and tcp_control?(transport, sock_conn)
    }
  end

  # RFC 6062: ChannelData/Send are forbidden on a TCP-relay control 5-tuple.
  # UDP/DTLS never consult ETS. Stream clients use the O(1) allocation flag.
  defp tcp_control?(transport, sock_conn) do
    transport.framing() == :stream and Store.tcp_allocation?(tuple5_of(sock_conn))
  end

  defp tuple5_of(sock_conn) do
    conn = %Conn{
      client_ip: sock_conn.client_ip,
      client_port: sock_conn.client_port,
      server_ip: sock_conn.server_ip,
      server_port: sock_conn.server_port,
      client_socket: nil
    }

    Tuple5.to_map(Tuple5.create(conn, :_))
  end

  defp process_connection_bind(frame, sock_conn, transport) do
    PacketLog.incoming(frame, sock_conn.client_ip, sock_conn.client_port)

    client_socket =
      ClientSocket.new(
        transport,
        sock_conn.socket,
        sock_conn.client_ip,
        sock_conn.client_port
      )

    xconn = %Conn{
      message: frame,
      client_ip: sock_conn.client_ip,
      client_port: sock_conn.client_port,
      server_ip: sock_conn.server_ip,
      server_port: sock_conn.server_port,
      client_socket: client_socket
    }

    case Pipeline.process_message(xconn) do
      %Conn{splice_peer: peer_socket} = result when is_port(peer_socket) ->
        case Conn.to_reply(result) do
          {:ok, iodata} ->
            PacketLog.outgoing(iodata, sock_conn.client_ip, sock_conn.client_port)
            _ = ClientSocket.send(client_socket, iodata)
            TcpRegistry.mark_spliced(sock_conn.socket)
            Xirsys.XTurn.Allocate.Client.start_splice(sock_conn.socket, peer_socket)

          _ ->
            :ok
        end

      %Conn{} = result ->
        case Conn.to_reply(result) do
          {:ok, iodata} ->
            PacketLog.outgoing(iodata, sock_conn.client_ip, sock_conn.client_port)
            ClientSocket.send(client_socket, iodata)

          _ ->
            :ok
        end

      _ ->
        :ok
    end
  end
end
