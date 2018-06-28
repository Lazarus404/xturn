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

defmodule Xirsys.Turn.Allocate.Client do
  @moduledoc """
  """
  use GenServer
  require Logger
  @vsn "0"

  @default_lifetime 600
  @channel_lifetime 600_000
  @permission_lifetime 300_000

  alias Xirsys.Turn.Allocate.{State, Store, Client}
  alias Xirsys.Turn.Channels.Store, as: Channels
  alias Xirsys.Turn.Channels.Channel, as: Channel
  alias Xirsys.Turn.Tuple5
  alias Xirsys.Stun
  alias Xirsys.Utils.Socket, as: SocketHelpers
  alias Xirsys.Utils.Timing, as: Time

  #########################################################################################################################
  # Interface functions
  #########################################################################################################################

  def start_link(id, listener, tuple5, lifetime),
    do: GenServer.start_link(__MODULE__, [id, listener, tuple5, lifetime])

  def create(id, listener, tuple5, lifetime),
    do: Xirsys.Turn.Allocate.Supervisor.start_child(id, listener, tuple5, lifetime)
  def create(id, listener, tuple5),
    do: create(id, listener, tuple5, @default_lifetime)

  def destroy(pid),
    do: Xirsys.Turn.Allocate.Supervisor.terminate_child(pid)

  def refresh(pid, lifetime),
    do: GenServer.cast(pid, {:refresh, lifetime})

  def count() do
    pid = Process.whereis(Xirsys.Turn.Allocate.Supervisor)
    %{workers: workers} = Supervisor.count_children(pid)
    {:ok, workers}
  end

  def open_port_random(pid),
    do: open_port_random(pid, [])
  def open_port_random(pid, opts),
    do: GenServer.call(pid, {:open_port, :random, opts})

  def open_port_preferred(pid, port),
    do: open_port_preferred(pid, port, [])
  def open_port_preferred(pid, port, opts),
    do: GenServer.call(pid, {:open_port, {:preferred, port}, opts})

  def open_port_range(pid, min, max),
    do: open_port_range(pid, min, max, [])
  def open_port_range(pid, min, max, opts),
    do: GenServer.call(pid, {:open_port, {:range, min, max}, opts})

  def get_permission_cache(pid),
    do: GenServer.call(pid, :get_permission_cache)

  def set_peer_details(pid, ns, peer_id),
    do: GenServer.cast(pid, {:set_peer_details, ns, peer_id})

  def dont_fragment(pid),
    do: GenServer.call(pid, :dont_fragment)

  def clear_header(pid),
    do: GenServer.call(pid, :clear_header)

  def set_relay_address(pid, relay_address),
    do: GenServer.cast(pid, {:relay_address, relay_address})

  def add_permissions(pid, perms) when is_tuple(perms),
    do: GenServer.cast(pid, {:add_permissions, perms})

  def add_peer_channel(pid, channel_number, peer_address),
    do: GenServer.call(pid, {:add_channel, channel_number, peer_address})

  def remove_peer_channel(pid, channel_number, peer_address),
    do: GenServer.call(pid, {:remove_channel, channel_number, peer_address})

  def refresh_channel(pid, id),
    do: GenServer.cast(pid, {:refresh_channel, id})

  def send_channel(pid, channel, data, socket \\ nil, channel_cache \\ nil)
  def send_channel(pid, channel, <<_::binary>> = data, _, nil) when is_integer(channel),
    do: GenServer.cast(pid, {:send_channel, channel, data})
  def send_channel(pid, channel, <<_::binary>> = data, socket, channel_cache) when is_integer(channel) do
    send_data_channel(channel, data, socket, channel_cache)
    GenServer.cast(pid, {:log_data, data})
  end

  def send_indication(pid, peer_address, data, socket \\ nil, perms \\ nil)
  def send_indication(pid, {_, _} = peer_address, <<_::binary>> = data, nil, _perms),
    do: GenServer.cast(pid, {:send_indication, peer_address, data})
  def send_indication(pid, {pip, pport}, <<_::binary>> = data, socket, perms) do
    case Xirsys.Turn.Cache.Store.has_key?(perms, pip) do
      true ->
        Client.send_data(data, pip, pport, socket)
        GenServer.cast(pid, {:log_data, data})
      _ ->
        :ok
    end
  end

  #########################################################################################################################
  # OTP functions
  #########################################################################################################################

  def init([id, listener, tuple5, lifetime]) do
    {:ok, perms} = Xirsys.Turn.Cache.Store.init(@permission_lifetime)
    {:ok, chans} = Xirsys.Turn.Cache.Store.init(@channel_lifetime, fn id -> Logger.info "CHANNEL #{inspect id} REMOVED" end )
    {:ok, %State{
                  id: id,
                  listener: listener,
                  tuple5: tuple5,
                  refresh_time: Time.now(),
                  lifetime: lifetime,
                  peer_started: Time.local_time(),
                  permissions: perms,
                  channels: chans
                }, Time.milliseconds_left(Time.now(), lifetime)}
  end

  def handle_info(:timeout, state),
    do: {:stop, :normal, state}
  def handle_info({:udp, socket, ip, in_port, packet}, state) do
    Logger.debug "udp data sent from peer #{inspect ip}:#{inspect in_port} in genserver #{inspect self()}"
    Logger.debug "#{inspect state}"
    bytes_in =
    with true <- Xirsys.Turn.Cache.Store.has_key?(state.permissions, ip) and require_perms() do
      length = byte_size(packet)
      peer_address = {ip, in_port}
      Logger.debug "sending #{inspect length} bytes to client"
      data =
      case Channels.lookup({peer_address, Tuple5.to_map(state.tuple5)}) do
        {:ok, [[channel_number, _client]|_]} ->
          chan_packet = <<channel_number::16, length::16>> <> packet
          Logger.debug "sending #{inspect byte_size(chan_packet)} bytes (with header) to client"
          chan_packet
        _ ->
          attrs = %{}
          tmp_attrs = Map.put(attrs, :xor_peer_address, {ip, in_port})
          data_attrs = Map.put(tmp_attrs, :data, packet)
          <<tid::96>> = :crypto.strong_rand_bytes(12)
          conn = %Stun{class: :indication, method: :data, transactionid: tid, integrity: :false, fingerprint: :false, attrs: data_attrs}
          Stun.encode(conn)
      end
      GenServer.cast(state.listener, {data, state.tuple5.client_address, state.tuple5.client_port})
      byte_size(data)
    else
      _ ->
        Logger.info "peer permission not available #{inspect state.tuple5}"
        0
    end
    :inet.setopts(socket, [{:active, :once}, :binary])
    {:noreply, %State{state | bytes_in: state.bytes_in + bytes_in}, Time.milliseconds_left(state)}
  end

  def handle_call({:open_port, :random = policy, opts}, from, state),
    do: open_port_call({policy, opts}, from, state)
  def handle_call({:open_port, {:preferred, _port} = policy, opts}, from, state),
    do: open_port_call({policy, opts}, from, state)
  def handle_call({:open_port, {:range, _min, _max} = policy, opts}, from, state),
    do: open_port_call({policy, opts}, from, state)
  def handle_call(:get_permission_cache, _from, state),
    do: {:reply, {:ok, state.permissions}, state, Time.milliseconds_left(state)}
  def handle_call(:dont_fragment, _from, state),
    do: :inet.setopts(state.relayed_socket,[{:raw,0,10,<<2::native-size(32)>>}])
  def handle_call(:clear_header, _from, state),
    do: :inet.setopts(state.relayed_socket,[{:raw,0,10,<<0::native-size(32)>>}])
  def handle_call({:add_channel, channel_number, peer_address}, _from, state) do
    channel = %Channel{id: channel_number,
                       tuple5: state.tuple5,
                       peer_address: peer_address}
    Logger.debug "ADDING CHANNEL #{inspect channel_number}"
    Channels.insert(channel_number, self(), peer_address, state.tuple5, state.relayed_socket, state.channels)
    Xirsys.Turn.Cache.Store.append_item_to_store(state.channels, {channel_number, channel})
    {:reply, :ok, state, Time.milliseconds_left(state)}
  end
  def handle_call({:remove_channel, channel_number}, _from, state) do
    Channels.delete(channel_number)
    Xirsys.Turn.Cache.Store.remove_item_from_store(state.channels, channel_number)
    {:reply, :ok, state, Time.milliseconds_left(state)}
  end
  def handle_call({:remove_permission, id}, _from, state) do
    Xirsys.Turn.Cache.Store.remove_item_from_store(state.permissions, id)
    {:reply, :ok, state, Time.milliseconds_left(state)}
  end

  def handle_cast({:add_permissions, perm}, state) do
    Logger.debug "adding permissions #{inspect state.permissions} #{inspect perm} #{inspect state.tuple5}"
    Xirsys.Turn.Cache.Store.append_item_to_store(state.permissions, perm)
    {:noreply, state, Time.milliseconds_left(state)}
  end
  def handle_cast({:relay_address, relay_address}, state),
    do: {:noreply, %State{state | relayed_address: relay_address}, Time.milliseconds_left(state)}
  def handle_cast({:set_peer_details, ns, peer_id}, state),
    do: {:noreply, %State{state | ns: ns, peer_id: peer_id}, Time.milliseconds_left(state)}
  def handle_cast({:refresh, lifetime}, state) do
    {:noreply, %State{state | refresh_time: Time.now()}, Time.milliseconds_left(Time.now(), lifetime)}
  end
  def handle_cast({:refresh_channel, id}, state) do
    Xirsys.Turn.Cache.Store.append_item_to_store(state.channels, {id, :nil})
    {:noreply, state, Time.milliseconds_left(state)}
  end
  def handle_cast({:send_channel, channel_number, data}, state) do
    bytes_out = send_data_channel(channel_number, data, state.relayed_socket, state.channels)
    {:noreply, %State{state | bytes_out: state.bytes_out + bytes_out}, Time.milliseconds_left(state)}
  end
  def handle_cast({:send_indication, {pip, pport} = _peer_address, data}, state) do
    bytes_out = case Xirsys.Turn.Cache.Store.has_key?(state.permissions, pip) do
      true ->
        send_data(data, pip, pport, state)
        byte_size(data)
      _ ->
        0
    end
    {:noreply, %State{state | bytes_out: state.bytes_out + bytes_out}, Time.milliseconds_left(state)}
  end
  def handle_cast({:log_data, data}, state) do
    bytes_out = byte_size(data)
    {:noreply, %State{state | bytes_out: state.bytes_out + bytes_out}, Time.milliseconds_left(state)}
  end

  def terminate(reason, state) do
    Logger.info "Terminating with state : #{inspect reason}"
    if (state.relayed_socket),
      do: :gen_udp.close(state.relayed_socket)
    Xirsys.Turn.Cache.Store.keys(state.channels)
    |> Channels.delete()
    Xirsys.Turn.Cache.Store.terminate(state.channels)
    Store.delete(state.id)
    :ok
  end

  #########################################################################################################################
  # Helper functions
  #########################################################################################################################

  defp open_port_call({policy, opts}, _from, state) do
    case SocketHelpers.open_turn_port(Utils.server_local_ip(), policy, opts) do
      {:ok, socket} ->
        {:ok, port} = :inet.port(socket)
        {:reply, {:ok, socket, port}, %State{state | relayed_socket: socket}, Time.milliseconds_left(state)}
      {:error, reason} ->
        {:reply, {:error, reason}, state, Time.milliseconds_left(state)}
    end
  end

  defp require_perms() do
    case Application.get_env(:xturn, :permissions) do
      %{required: required} -> required
      _ -> true
    end
  end

  def send_data(msg, state) do
    t5 = state.tuple5
    Logger.debug "Returning data on #{inspect t5.client_address}:#{inspect t5.client_port}"
    send_data(msg, t5.client_address, t5.client_port, state)
  end
  def send_data(msg, cip, cport, state) when is_map(state) do
    Logger.debug "POSTING to #{inspect cip}:#{inspect cport} on relayed socket #{inspect state.relayed_socket}"
    :gen_udp.send(state.relayed_socket, cip, cport, msg)
  end
  def send_data(msg, cip, cport, socket) do
    Logger.debug "POSTING to #{inspect cip}:#{inspect cport} on socket #{inspect socket}"
    :gen_udp.send(socket, cip, cport, msg)
  end

  def send_data_channel(channel_number, data, socket, channel_cache) do
    {:ok, channel} = Xirsys.Turn.Cache.Store.fetch(channel_cache, channel_number)
    {pip, pport} = channel.peer_address
    send_data(data, pip, pport, socket)
    byte_size(data)
  end
end