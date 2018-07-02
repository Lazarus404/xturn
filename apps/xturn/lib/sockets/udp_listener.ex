###----------------------------------------------------------------------
###
### Copyright (c) 2013 - 2018 Lee Sylvester and Xirsys LLC<lee.sylvester@gmail.com>
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
###----------------------------------------------------------------------

defmodule Xirsys.Sockets.UDP_Listener do
  @moduledoc """
  UDP protocol socket handler for STUN connections
  """
  use GenServer
  require Logger
  @vsn "0"

  @buf_size 1024*1024*1024
  @opts [active: false,
         buffer: @buf_size,
         recbuf: @buf_size,
         sndbuf: @buf_size]

  alias Xirsys.Turn.Conn
  alias Xirsys.Utils.Socket, as: Utils

  #####
  # External API

  @doc """
  Standard OTP module startup
  """
  def start_link(cb, ip, port) do
    GenServer.start_link(__MODULE__, [cb, ip, port, false])
  end

  def start_link(cb, ip, port, ssl) do
    GenServer.start_link(__MODULE__, [cb, ip, port, ssl], [debug: [:statistics]])
  end

  @doc """
  Initialises connection with IPv6 address
  """
  def init([cb, {_, _, _, _, _, _, _, _} = ip, port, ssl]) do
    opts = @opts ++ [ip: ip] ++ [:binary, :inet6]
    open_socket(cb, ip, port, ssl, opts)
  end

  @doc """
  Initialises connection with IPv4 address
  """
  def init([cb, {_, _, _, _} = ip, port, ssl]) do
    opts = @opts ++ [ip: ip] ++ [:binary]
    open_socket(cb, ip, port, ssl, opts)
  end

  def handle_call(other, _from, state) do
    Logger.error "UDP listener: strange call: #{inspect other}"
    {:noreply, state}
  end

  @doc """
  Asynchronous socket response handler
  """
  def handle_cast({msg, ip, port}, state) do
    :gen_udp.send(state.socket, ip, port, msg)
    {:noreply, state}
  end

  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end

  def handle_cast(other, state) do
    Logger.error "UDP listener: strange cast: #{inspect other}"
    {:noreply, state}
  end

  def handle_info(:timeout, state) do
    :inet.setopts(state.socket, [{:active, :once}, :binary])
    :erlang.process_flag(:priority, :high)
    {:noreply, state}
  end

  @doc """
  Message handler for incoming UDP STUN packets
  """
  def handle_info({:udp, _fd, fip, fport, msg}, state) do
    Logger.debug "UDP called #{inspect byte_size(msg)} bytes"
    {:ok, {_, tport}} = :inet.sockname(state.socket)
    spawn(state.callback, :process_message, [%Conn{
        message: msg,
        listener: self(),
        client_ip: fip,
        client_port: fport,
        server_ip: Utils.server_ip(),
        server_port: tport
      }])
    :inet.setopts(state.socket, [{:active, :once}, :binary])
    :erlang.process_flag(:priority, :high)
    {:noreply, state}
  end

  def handle_info(info, state) do
    Logger.error "UDP listener: strange info: #{inspect info}"
    {:noreply, state}
  end

  def code_change(_old_vsn, state, _extra) do
    {:ok, state}
  end

  def terminate(reason, %{ssl: true} = state) do
    :ssl.close(state.socket)
    Logger.debug "DTLS listener closed: #{inspect reason}"
    :ok
  end
  def terminate(reason, state) do
    :gen_udp.close(state.socket)
    Logger.debug "UDP listener closed: #{inspect reason}"
    :ok
  end

  @doc """
  Apply specific socket option for STUN connection
  """
  def set_sockopt(list_sock, cli_socket) do
    # true = :inet_db.register_socket(cli_socket, :inet_udp)
    try do
      {:ok, opts} = :ssl.getopts(list_sock, [:active, :nodelay, :keepalive, :delay_send, :priority, :tos, :buffer, :recbuf, :sndbuf])
      :ssl.setopts(cli_socket, opts)
      :ok
    rescue
      e ->
        Logger.error "damn #{inspect e}"
        close(cli_socket)
    end
  end

  defp open_socket(cb, ip, port, ssl, opts) do
    Logger.info "UDP listener #{inspect self()} started at [#{:inet_parse.ntoa(ip)}:#{port}]"
    with true <- valid_ip?(ip) do
      case ssl do
        true ->
          {:ok, certs} = :application.get_env(:certs)
          nopts = opts ++ certs ++ [protocol: :dtls]
          {:ok, fd} = :ssl.listen(port, nopts)
          Xirsys.Sockets.TCP_Client.create(fd, cb, ssl)
          {:ok, %{listener: fd, ssl: ssl}}
        _ ->
          {:ok, fd} = :gen_udp.open(port, opts)
          {:ok, %{socket: fd, callback: cb, ssl: ssl}, 0}
      end
    else
      false -> {:error, :invalid_ip_address}
      e -> e
    end
  end

  def close(nil) do
    Logger.debug "Caught attempted close of nil socket"
  end
  def close({:sslsocket, _, _} = socket) do
    :ssl.close(socket)
  end
  def close(socket) when socket != nil do
    :gen_udp.close(socket)
  end

  defp valid_ip?(ip),
    do: Enum.reduce(Tuple.to_list(ip), true, &(is_integer(&1) and &1 >= 0 and &1 < 65535 and &2))
end