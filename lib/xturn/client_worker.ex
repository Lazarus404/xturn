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

defmodule Xirsys.XTurn.ClientWorker do
  @moduledoc """
  GenServer shard that runs the STUN/TURN control pipeline.

  ## What problem this solves

  Control requests from many clients must not block each other on one process.
  The pool hashes each client endpoint to a worker; this GenServer builds
  `%Conn{}`, runs `Pipeline.process_message/1`, encodes replies, and sends
  them on the client socket or an RFC 5780 alternate path.

  ## Internal note

  Started by `ClientWorker.Pool`; not invoked by operators.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN control methods)
  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (alternate reply routing)
  """
  use GenServer
  require Logger

  alias Xirsys.XTurn.{ClientSocket, Conn, PacketLog, Pipeline}

  @doc "Starts a named worker; `:name` is required in `opts`."
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc false
  @impl true
  def init(_opts), do: {:ok, %{}}

  @doc false
  @impl true
  def handle_cast({:process, frame, meta}, state) do
    process_packet(frame, meta)
    {:noreply, state}
  end

  defp process_packet(frame, meta) do
    PacketLog.incoming(frame, meta.client_ip, meta.client_port)

    client_socket =
      ClientSocket.new(
        meta.transport,
        meta.socket,
        meta.client_ip,
        meta.client_port
      )

    xconn = %Conn{
      message: frame,
      client_ip: meta.client_ip,
      client_port: meta.client_port,
      server_ip: meta.server_ip,
      server_port: meta.server_port,
      client_socket: client_socket
    }

    case Pipeline.process_message(xconn) do
      %Conn{} = result ->
        case Conn.to_reply(result) do
          {:ok, iodata} ->
            PacketLog.outgoing(iodata, meta.client_ip, meta.client_port)
            send_reply(result, iodata)

          :noreply ->
            Logger.debug(
              "client worker: no reply for #{inspect(meta.client_ip)}:#{inspect(meta.client_port)} " <>
                "(halt=#{inspect(result.halt)}, response=#{inspect(result.response)})"
            )
        end

      false ->
        Logger.debug(
          "client worker: pipeline returned false for #{inspect(meta.client_ip)}:#{inspect(meta.client_port)}"
        )
    end
  end

  defp send_reply(%Conn{reply_from: {transport, socket}, reply_to: {ip, port}} = _conn, data)
       when not is_nil(socket) do
    case transport.send(socket, data, {ip, port}) do
      :ok -> :ok
      {:error, reason} -> log_send_failure(ip, port, reason)
    end
  end

  defp send_reply(%Conn{client_socket: client_socket} = _conn, data) do
    case ClientSocket.send(client_socket, data) do
      :ok -> :ok
      {:error, reason} ->
        log_send_failure(client_socket.client_ip, client_socket.client_port, reason)
    end
  end

  defp log_send_failure(ip, port, reason) do
    Logger.debug(
      "client worker: send failed for #{inspect(ip)}:#{inspect(port)}: #{inspect(reason)}"
    )
  end
end
