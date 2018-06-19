###----------------------------------------------------------------------
###
### Copyright (c) 2014 Lee Sylvester <lee.sylvester@gmail.com>
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

  alias Xirsys.Turn.Conn

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
  def init([cb, {i0, i1, i2, i3, i4, i5, i6, i7} = ipv6, port, _ssl]) when
    is_integer(i0) and i0 >= 0 and i0 < 65535 and
    is_integer(i1) and i1 >= 0 and i1 < 65535 and
    is_integer(i2) and i2 >= 0 and i2 < 65535 and
    is_integer(i3) and i3 >= 0 and i3 < 65535 and
    is_integer(i4) and i4 >= 0 and i4 < 65535 and
    is_integer(i5) and i5 >= 0 and i5 < 65535 and
    is_integer(i6) and i6 >= 0 and i6 < 65535 and
    is_integer(i7) and i7 >= 0 and i7 < 65535 do
    {:ok, fd} = :gen_udp.open(port, [{:ip, ipv6}, {:active, false}, {:buffer, 1024*1024*16}, {:recbuf, 1024*1024*16}, {:sndbuf, 1024*1024*16}, :binary, :inet6])
    Logger.info "UDP listener #{inspect self()} started at [#{:inet_parse.ntoa(ipv6)}:#{port}]"
    {:ok, %{:socket => fd, :callback => cb}, 0}#, :pid => pid}}
  end

  @doc """
  Initialises connection with IPv4 address
  """
  def init([cb, {i0, i1, i2, i3} = ipv4, port, _ssl]) when
    is_integer(i0) and i0 >= 0 and i0 < 256 and
    is_integer(i1) and i1 >= 0 and i1 < 256 and
    is_integer(i2) and i2 >= 0 and i2 < 256 and
    is_integer(i3) and i3 >= 0 and i3 < 256 do
    {:ok, fd} = :gen_udp.open(port, [{:ip, ipv4}, {:active, false}, {:buffer, 1024*1024*1024}, {:recbuf, 1024*1024*1024}, {:sndbuf, 1024*1024*1024}, :binary])
    Logger.info "UDP listener #{inspect self()} started at [#{:inet_parse.ntoa(ipv4)}:#{port}]"
    {:ok, %{:socket => fd, :callback => cb}, 0}#, :pid => pid}}
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
  Message handler for incoming STUN packets
  """
  def handle_info({:udp, _fd, fip, fport, msg}, state) do
    Logger.debug "UDP called #{inspect byte_size(msg)} bytes"
    {:ok, {tip, tport}} = :inet.sockname(state.socket)
    spawn(state.callback, :process_message, [%Conn{
        message: msg,
        listener: self(),
        client_ip: fip,
        client_port: fport,
        server_ip: tip,
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

  def terminate(reason, state) do
    :gen_udp.close(state.socket)
    Logger.debug "UDP listener closed: #{inspect reason}"
    :ok
  end
end