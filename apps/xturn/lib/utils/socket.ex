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

defmodule Xirsys.Utils.Socket do
  @moduledoc """
  Socket protocol helpers
  """
  require Logger
  alias Xirsys.Turn.Conn
  alias Xirsys.Utils.Socket

  defstruct type: :udp, sock: nil

  @type t :: {
              type :: :udp | :tcp | :dtls | :tls,
              sock :: any()
            }

  @channel_msg 1
  @send_msg 0

  @doc """
  Returns the server ip from config for packet use
  """
  @spec server_ip() :: tuple()
  def server_ip(),
    do: Application.get_env(:xturn, :server_ip, {0, 0, 0, 0})

  @doc """
  Returns the servers local ip from the config
  """
  @spec server_local_ip() :: tuple()
  def server_local_ip(),
    do: Application.get_env(:xturn, :server_local_ip, {0, 0, 0, 0})

  @doc """
  Opens a new port for UDP TURN transport
  """
  def open_turn_port({_, _, _, _} = sip, policy, opts) do
    udp_options = [{:ip, sip}, {:active, :once}, {:buffer, 1024*1024*1024}, {:recbuf, 1024*1024*1024}, {:sndbuf, 1024*1024*1024}, :binary] ++ opts #[{:buffer, 1024*1024*1024}, {:recbuf, 1024*1024*1024}, {:sndbuf, 1024*1024*1024}, {:exit_on_close, true}, {:keepalive, true}, {:nodelay, true}, {:packet, :raw}]
    open_free_udp_port(policy, udp_options)
  end

  @doc """
  With new data, see if we can process a message on the buffer
  """
  def process_buffer(data, buffer, addr, callback) do
    bin = <<buffer::binary, data::binary>>
    process_buffer(bin, addr, callback)
  end

  defp process_buffer(bin, _, _) when byte_size(bin) <= 4, do: bin
  defp process_buffer(<<type::2, _::14, body_bytes::16, _body::binary-size(body_bytes), _::binary>> = bin, addr, callback) when type == @send_msg
                                                                                                                             or type == @channel_msg do
    msg_bytes = pad_body_bytes(type, body_bytes)
    process_data(bin, msg_bytes, addr, callback)
  end
  defp process_buffer(<<type::2, _::14, _body_bytes::16, _::binary>> = bin, _, _) when type == @send_msg or type == @channel_msg,
    do: bin # message is not yet long enough
  defp process_buffer(<<type::2, _::14, _::binary>> = bin, _, _) do
    Logger.error "Unknown message type : #{inspect type}"
    bin
  end

  @doc """
  With a packet header extracted from the buffer,  see
  if we can process it
  """
  defp process_data(bin, required_size, _, _) when required_size > byte_size(bin), do: bin # need more data
  defp process_data(bin, required_size, {{cip, cport}, {sip, sport}}, callback) when required_size == byte_size(bin) do
    process_msg(callback, bin, {self(), cip, cport, sip, sport})
    <<>>
  end
  defp process_data(bin, required_size, {{cip, cport}, {sip, sport}} = addr, callback) do
    # parse TURN message
    <<turn::binary-size(required_size), tail::binary>> = bin
    Logger.debug "Tail is: #{inspect tail}"
    #ns = process_turn_msg(turn, %{state | turn_msg_buffer: bin})
    process_msg(callback, turn, {self(), cip, cport, sip, sport})
    process_buffer(tail, addr, callback)
  end

  defp pad_body_bytes(@channel_msg, bytes),
    do: roundup_to_4(bytes)
  defp pad_body_bytes(@send_msg, bytes),
    do: bytes + 20

  @doc """
  Pad message if needed
  """
  defp roundup_to_4(num) do
    pad = rem(num, 4)
    padded = num+(4-pad)
    if rem(num, 4) == 0, do: padded, else: padded + 4
  end

  @doc """
  Calls the callback handler
  """
  defp process_msg(cb, msg, {listener, fip, fport, tip, tport}) do
    apply cb, :process_message, [%Conn{
        message: msg,
        listener: listener,
        client_ip: fip,
        client_port: fport,
        server_ip: tip,
        server_port: tport
      }]
  end

  @doc """
  Opens an available UDP port as per requirement.
  See RFC's
  """
  defp open_free_udp_port(:random, udp_options) do
    ## BUGBUG: Should be a random port
    case :gen_udp.open(0, udp_options) do
      {:ok, socket} ->
        {:ok, %Socket{type: :udp, sock: socket}}
      {:error, reason} ->
        Logger.error "UDP open #{inspect udp_options} -> #{inspect reason}"
        {:error, reason}
      {EXIT, _} = reason ->
        Logger.error "UDP open #{inspect udp_options} -> #{inspect reason}"
        {:error, reason}
    end
  end
  defp open_free_udp_port({:range, min_port, max_port}, udp_options) when min_port <= max_port do
    case :gen_udp.open(min_port, udp_options) do
      {:ok, socket} ->
        {:ok, %Socket{type: :udp, sock: socket}}
      {:error, :eaddrinuse} ->
        policy2 = {:range, min_port + 1, max_port}
        open_free_udp_port(policy2, udp_options)
      {:error, reason} ->
        Logger.error "UDP open #{inspect [0 | udp_options]} -> #{inspect reason}"
        {:error, reason}
      {EXIT, _} = reason ->
        Logger.error "UDP open #{inspect [0 | udp_options]} -> #{inspect reason}"
        {:error, reason}
    end
  end
  defp open_free_udp_port({:range, _min_port, _max_port}, udp_options) do
    reason = "Port range exhausted"
    Logger.error "UDP open #{inspect [0 | udp_options]} -> #{inspect reason}"
    {:error, reason}
  end
  defp open_free_udp_port({:preferred, port}, udp_options) do
    case :gen_udp.open(port, udp_options) do
      {:ok, socket} ->
        {:ok, %Socket{type: :udp, sock: socket}}
      {:error, :eaddrinuse} ->
        policy2 = :random
        open_free_udp_port(policy2, udp_options)
      {:error, reason} ->
        Logger.error "UDP open #{inspect [0 | udp_options]} -> #{inspect reason}"
        {:error, reason}
      {EXIT, _} = reason ->
        Logger.error "UDP open #{inspect [0 | udp_options]} -> #{inspect reason}"
        {:error, reason}
    end
  end

  def handshake(%Socket{type: :tcp, sock: socket}) do
    with {:ok, cli_socket} <- :gen_tcp.accept(socket) do
      {:ok, %Socket{type: :tcp, sock: cli_socket}}
    end
  end
  def handshake(%Socket{type: type, sock: socket}) do
    with {:ok, cli_socket} <- :ssl.transport_accept(socket),
         {:ok, cli_socket} <- :ssl.handshake(cli_socket) do
      {:ok, %Socket{type: type, sock: cli_socket}}
    end
  end

  @doc """
  Sends a message over an open udp socket port
  """
  @spec send(Socket.t, tuple(), integer(), binary()) :: :ok | {:error, term()}
  def send(%Socket{type: :udp, sock: socket}, ip, port, msg),
    do: :gen_udp.send(socket, ip, port, msg)

  @doc """
  Sends a message over an open accepted socket port
  """
  @spec send(Socket.t, binary()) :: :ok | {:error, term()}
  def send(%Socket{type: :tcp, sock: socket}, msg),
    do: :gen_tcp.send(socket, msg)
  def send(%Socket{type: :dtls, sock: socket}, msg),
    do: :ssl.send(socket, msg)
  def send(%Socket{type: :tls, sock: socket}, msg),
    do: :ssl.send(socket, msg)

  @doc """
  Sets one or more options for a socket.
  """
  @spec setopts(Socket.t) :: :ok | {:error, term()}
  def setopts(%Socket{type: type, sock: socket}) when type in [:udp, :tcp],
    do: :inet.setopts(socket, [{:active, :once}, :binary])
  def setopts(%Socket{type: _, sock: socket}),
    do: :ssl.setopts(socket, [{:active, :once}, :binary])

  @spec setopts(Socket.t, list()) :: :ok | {:error, term()}
  def setopts(%Socket{type: type, sock: socket}, opts) when type in [:udp, :tcp],
    do: :inet.setopts(socket, opts)
  def setopts(%Socket{type: _, sock: socket}, opts),
    do: :ssl.setopts(socket, opts)

  def getopts(%Socket{type: type, sock: socket}) when type in [:tls, :dtls],
    do: :ssl.getopts(socket, [:active, :nodelay, :keepalive, :delay_send, :priority, :tos, :buffer, :recbuf, :sndbuf])
  def getopts(%Socket{sock: socket}),
    do: :inet.getopts(socket, [:active, :nodelay, :keepalive, :delay_send, :priority, :tos, :buffer, :recbuf, :sndbuf])

  @doc """
  Apply specific socket option for STUN connection
  """
  @spec set_sockopt(Socket.t, Socket.t) :: :ok
  def set_sockopt(%Socket{type: type} = list_sock, %Socket{type: type} = cli_socket) when type in [:tls, :dtls] do
    try do
      {:ok, opts} = getopts(list_sock)
      setopts(cli_socket, opts)
      :ok
    rescue
      e ->
        Logger.error "damn #{inspect e}"
        close(cli_socket)
    end
  end
  def set_sockopt(%Socket{type: :tcp} = list_sock, %Socket{type: :tcp} = cli_socket) do
    true = register_socket(cli_socket)
    try do
      {:ok, opts} = getopts(list_sock)
      setopts(cli_socket, opts)
      :ok
    rescue
      e ->
        Logger.error "damn #{inspect e}"
        close(cli_socket)
    end
  end

  def register_socket(%Socket{type: :tcp, sock: socket}),
    do: :inet_db.register_socket(socket, :inet_tcp)

  @doc """
  Returns the local address and port number for a socket.
  """
  @spec sockname(Socket.t) :: {:ok, {tuple(), integer()}} | {:local, binary()} | {:unspec, <<>>} | {:undefined, any()} | {:error, term()}
  def sockname(%Socket{type: type, sock: socket}) when type in [:udp, :tcp],
    do: :inet.sockname(socket)
  def sockname(%Socket{type: type, sock: socket}) when type in [:dtls, :tls],
    do: :ssl.sockname(socket)

  @doc """
  Returns the peer address and port number for a socket.
  """
  @spec peername(Socket.t | any()) :: {:ok, {tuple(), integer()}} | {:local, binary()} | {:unspec, <<>>} | {:undefined, any()} | {:error, term()}
  def peername(%Socket{type: type, sock: socket}) when type in [:udp, :tcp],
    do: :inet.peername(socket)
  def peername(%Socket{type: type, sock: socket}) when type in [:dtls, :tls],
    do: :ssl.peername(socket)

  def port(%Socket{type: :udp, sock: sock}),
    do: :inet.port(sock)

  @doc """
  Closes a socket of any type.s
  """
  @spec close(Socket.t) :: :ok
  def close(sock, reason \\ "")
  def close(%Socket{type: :udp, sock: socket}, reason) do
    :gen_udp.close(socket)
    Logger.debug "UDP listener closed: #{inspect reason}"
  end
  def close(%Socket{type: :tcp, sock: socket}, reason) do
    :gen_tcp.close(socket)
    Logger.debug "UDP listener closed: #{inspect reason}"
  end
  def close(%Socket{type: :dtls, sock: socket}, reason) do
    :ssl.close(socket)
    Logger.debug "DTLS listener closed: #{inspect reason}"
  end
  def close(%Socket{type: :tls, sock: socket}, reason) do
    :ssl.close(socket)
    Logger.debug "TLS listener closed: #{inspect reason}"
  end
  def close(nil, _),
    do: Logger.debug "Caught attempted close of nil socket"
end