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

defmodule Xirsys.XTurn.RelayIngress.Worker do
  @moduledoc """
  GenServer shard that owns relay UDP sockets and delivers peer packets to clients.

  ## What problem this solves

  Each relay ingress worker processes datagrams from peers that hit allocated
  relay ports. For each packet it verifies CreatePermission, wraps payload as
  ChannelData or a Data indication, and sends to the client socket. ICMP
  errors on relay sockets become STUN error indications to the client.

  Uses active UDP with a bounded drain (`udp_active_n - 1` extra messages per
  wakeup) to batch work without starving other processes.

  ## Internal

  One worker per shard under `RelayIngress`; not part of the public API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - permissions, Data indication, ChannelData (pt.8-11)
  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - ICMP error indication encoding
  """
  use GenServer

  alias XSockets.{Config, Transport.UDP}
  alias Xirsys.XTurn.Allocate.{Bytes, Client, Store}
  alias Xirsys.XTurn.Permissions.Store, as: Permissions
  alias Xirsys.XTurn.Plugin.Dispatch
  alias Xirsys.XTurn.{ClientSocket, DataPlane, StunHelper}

  @doc "Starts worker shard `index` registered at `via(index)`."
  def start_link(index) do
    GenServer.start_link(__MODULE__, index, name: via(index))
  end

  @doc "Registered atom name for shard `index`."
  def via(index), do: :"xturn_relay_ingress_#{index}"

  @doc false
  @impl true
  def init(_index), do: {:ok, %{}}

  @doc false
  @impl true
  def handle_info({:udp, socket, ip, in_port, packet}, state) do
    deliver_peer_packet(socket, {ip, in_port}, packet)
    sockets = drain_pending(MapSet.new([socket]), Config.udp_active_n() - 1)
    Enum.each(sockets, &rearm/1)
    {:noreply, state}
  end

  def handle_info({:udp_passive, socket}, state) do
    rearm(socket)
    {:noreply, state}
  end

  def handle_info({:udp_error, socket, reason}, state) do
    handle_icmp(socket, reason)
    {:noreply, state}
  end

  @doc false
  def handle_info(_msg, state), do: {:noreply, state}

  defp drain_pending(sockets, 0), do: sockets

  defp drain_pending(sockets, budget) do
    receive do
      {:udp, socket, ip, in_port, packet} ->
        deliver_peer_packet(socket, {ip, in_port}, packet)
        drain_pending(MapSet.put(sockets, socket), budget - 1)

      {:udp_error, socket, reason} ->
        handle_icmp(socket, reason)
        drain_pending(sockets, budget - 1)

      {:udp_passive, socket} ->
        drain_pending(MapSet.put(sockets, socket), budget - 1)
    after
      0 -> sockets
    end
  end

  defp rearm(socket), do: :inet.setopts(socket, Config.active_socket_opts())

  defp handle_icmp(socket, reason) do
    case UDP.handle_message({:udp_error, socket, reason}, socket) do
      {:icmp, %{type: type, code: code, error_data: error_data, peer: peer}} ->
        case Store.lookup_sock(socket) do
          {:ok, dest} ->
            data = StunHelper.icmp_indication(peer, type, code, error_data)
            ClientSocket.send(dest.client_socket, data)

          :error ->
            :ok
        end

      _ ->
        :ok
    end
  end

  defp deliver_peer_packet(socket, peer_address, packet) do
    with {:ok, dest} <- Store.lookup_sock(socket),
         {src_ip, _} <- peer_address,
         true <- not require_perms?() or Permissions.allowed?(dest.tuple5, src_ip) do
      framing =
        if Map.has_key?(dest.peer_to_channel, peer_address),
          do: :channel_data,
          else: :data_indication

      case plugin_ingress(dest.tuple5, packet, framing, peer_address) do
        {:ok, packet} ->
          data =
            DataPlane.to_client(
              packet,
              peer_address,
              dest.peer_to_channel,
              dest.client_socket
            )

          ClientSocket.send(dest.client_socket, data)
          Bytes.add_in(dest.pid, byte_size(data))

          if Permissions.due_refresh?(dest.tuple5, src_ip) do
            Permissions.grant(dest.tuple5, src_ip)
            Client.touch(dest.pid, src_ip, Map.get(dest.peer_to_channel, peer_address))
          end

          :ok

        :drop ->
          :drop
      end
    else
      _ -> :drop
    end
  end

  defp plugin_ingress(tuple5, payload, framing, peer_address) do
    if plugins_enabled?() do
      Dispatch.ingress(tuple5, payload, framing, peer_address)
    else
      {:ok, payload}
    end
  end

  defp plugins_enabled?(),
    do: :persistent_term.get({Xirsys.XTurn.Plugin, :enabled}, false)

  defp require_perms? do
    case Application.get_env(:xturn, :permissions) do
      %{required: required} -> required
      _ -> true
    end
  end
end
