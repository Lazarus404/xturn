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
### DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
### ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###
### ----------------------------------------------------------------------

defmodule Xirsys.XTurn.DataPlane do
  @moduledoc """
  Hot path for relayed TURN media (client to peer and hairpin).

  ## What problem this solves

  After a TURN allocation exists, most traffic is opaque media payloads, not
  STUN requests. Parsing every datagram fully would add latency. The data plane
  classifies frames with a slim header scan, checks permissions and channel
  bindings, applies optional plugins, and forwards UDP without entering the
  full control pipeline.

  When the peer is another allocation on the same server, packets hairpin back
  through ingress and `to_client/4` instead of leaving the host.

  ## Internal note

  Invoked from relay ingress and socket handlers; not an operator-facing API.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (ChannelData, Send indication, permissions)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TCP control allocations drop media here)
  """

  import Bitwise

  alias Xirsys.XTurn.Allocate.{Bytes, Client, Store}
  alias Xirsys.XTurn.Permissions.Store, as: Permissions
  alias Xirsys.XTurn.Channels.Store, as: Channels
  alias Xirsys.XTurn.Plugin.Dispatch
  alias Xirsys.XTurn.{ClientSocket, StunHelper, Tuple5}

  @stun_marker 0
  @class_request 0x0000
  @method_send 6
  @magic_cookie 0x2112A442
  @attr_xor_peer 0x0012
  @attr_data 0x0013
  @attr_fingerprint 0x8028
  @touch_interval_ms 60_000

  @typedoc """
  Data-plane socket metadata (`meta`): client/server endpoints, transport, socket,
  and `:is_control`.
  """
  @type meta :: %{
          client_ip: term(),
          client_port: term(),
          server_ip: term(),
          server_port: term(),
          transport: module(),
          socket: term(),
          is_control: boolean()
        }

  @doc """
  Classifies a relayed frame without full STUN decode.

  Returns `{:channel, number, payload}`, `{:send, peer, payload}`, `:control`,
  or `:ignore`.

  ## Examples

      iex> Xirsys.XTurn.DataPlane.classify(<<0x4000::16, 4::16, "ping">>)
      {:channel, 16384, "ping"}

      iex> alias XMediaLib.Stun
      iex> frame = Stun.encode(%Stun{
      ...>   class: :request,
      ...>   method: :binding,
      ...>   transactionid: 1,
      ...>   fingerprint: false,
      ...>   attrs: %{}
      ...> })
      iex> Xirsys.XTurn.DataPlane.classify(frame)
      :control

      iex> Xirsys.XTurn.DataPlane.classify(<<0xFF, 0xFF, 0x00>>)
      :ignore
  """
  @spec classify(binary()) ::
          {:channel, non_neg_integer(), binary()}
          | {:send, {term(), non_neg_integer()}, binary()}
          | :control
          | :ignore
  def classify(bin) do
    case bin do
      <<chan::16, length::16, rest::binary>> when (chan &&& 0xC000) == 0x4000 ->
        payload =
          if byte_size(rest) >= length do
            binary_part(rest, 0, length)
          else
            rest
          end

        {:channel, chan, payload}

      <<@stun_marker::2, m0::5, c0::1, m1::3, c1::1, m2::4, _len::16, _cookie::32, tid::96,
        attrs::binary>> ->
        method = (m0 <<< 7) ||| (m1 <<< 4) ||| m2
        class_bits = (c0 <<< 8) ||| (c1 <<< 4)

        cond do
          class_bits == @class_request ->
            :control

          c0 == 0 and c1 == 1 and method == @method_send ->
            case slim_send_attrs(attrs, tid) do
              {:ok, peer, data} -> {:send, peer, data}
              :error -> :ignore
            end

          true ->
            :ignore
        end

      _ ->
        :ignore
    end
  end

  @doc """
  Forwards ChannelData from the client to the bound peer.

  Accepts a raw frame (calls `classify/1`) or a pre-classified
  `{:channel, number, payload}` tuple. Returns `:ok`, `:not_found` when the
  channel is unbound, or `:drop` on control connections / plugin rejection.
  """
  @spec forward_channel(binary(), meta()) :: :ok | :not_found | :drop
  def forward_channel(frame, meta) when is_binary(frame),
    do: forward_channel(classify(frame), meta)

  @spec forward_channel({:channel, non_neg_integer(), binary()}, meta()) ::
          :ok | :not_found | :drop
  def forward_channel(_classified, %{is_control: true}), do: :drop

  def forward_channel({:channel, channel, payload}, meta) do
    do_forward_channel(channel, payload, meta)
  end

  def forward_channel(_classified, _meta), do: :drop

  @doc """
  Forwards a Send indication from the client to the peer.

  Accepts a raw frame or a pre-classified `{:send, peer, payload}` tuple.
  Checks allocation permissions, handles hairpin when the peer is local,
  and returns `:ok`, `:not_found`, or `:drop`.
  """
  @spec forward_send(binary(), meta()) :: :ok | :not_found | :drop
  def forward_send(frame, meta) when is_binary(frame),
    do: forward_send(classify(frame), meta)

  @spec forward_send({:send, {term(), non_neg_integer()}, binary()}, meta()) ::
          :ok | :not_found | :drop
  def forward_send(_classified, %{is_control: true}), do: :drop

  def forward_send({:send, peer, data}, meta) do
    do_forward_send(peer, data, meta)
  end

  def forward_send(_classified, _meta), do: :drop

  @doc """
  Encodes peer -> client traffic as ChannelData or a Data indication.

  When `peer_to_channel` maps `peer_address` to a channel number, emits a
  ChannelData frame (with stream padding when `client_socket.transport.framing()`
  is `:stream`). Otherwise builds a STUN Data indication via `StunHelper`.
  """
  @spec to_client(binary(), {term(), non_neg_integer()}, map(), term()) :: binary()
  def to_client(packet, peer_address, peer_to_channel, client_socket) do
    len = byte_size(packet)

    case Map.get(peer_to_channel, peer_address) do
      nil ->
        StunHelper.data_indication(packet, peer_address)

      channel_number ->
        format_channel_data(channel_number, len, packet, client_socket.transport.framing())
    end
  end

  defp do_forward_channel(channel, payload, meta) do
    tuple5 = tuple5_key(meta)

    case Channels.lookup(channel, tuple5) do
      {:ok, {client, peer_address, socket, relayed_address}} ->
        case plugin_egress(tuple5, payload, :channel_data, peer_address, channel) do
          {:ok, data} ->
            case forward_payload(data, meta, tuple5, client, peer_address, socket, relayed_address) do
              :ok ->
                {pip, _} = peer_address
                maybe_touch(client, tuple5, pip, channel)
                :ok

              other ->
                other
            end

          :drop ->
            :drop
        end

      {:error, :not_found} ->
        :not_found
    end
  end

  defp do_forward_send({pip, _} = peer_address, data, meta) do
    tuple5 = tuple5_key(meta)

    with {:ok, client, src_relay, socket, _perms} <- Store.lookup_tuple5(tuple5) do
      if require_perms?() and not Permissions.allowed?(tuple5, pip) do
        :drop
      else
        case plugin_egress(tuple5, data, :send_indication, peer_address, nil) do
          {:ok, data} ->
            source_addr = source_relay_address(socket, src_relay)

            case forward_payload(data, meta, tuple5, client, peer_address, socket, source_addr) do
              :ok ->
                maybe_touch(client, tuple5, pip, nil)
                :ok

              other ->
                other
            end

          :drop ->
            :drop
        end
      end
    else
      _ -> :not_found
    end
  end

  defp forward_payload(data, _meta, src_tuple5, client, peer_address, socket, source_addr) do
    case Store.lookup_relay(peer_address) do
      {:ok, dest} ->
        deliver_hairpin(dest, source_addr, data, src_tuple5)

      :error ->
        Client.send_channel(client, 0, data, socket, peer_address)
        Bytes.add_out(client, byte_size(data))
        :ok
    end
  end

  defp deliver_hairpin(_dest, source_addr, _payload, _src_tuple5)
       when not is_tuple(source_addr),
       do: :drop

  defp deliver_hairpin(dest, {src_ip, _} = source_addr, payload, _src_tuple5) do
    if require_perms?() and not Permissions.allowed?(dest.tuple5, src_ip) do
      :drop
    else
      case plugin_ingress(dest.tuple5, payload, framing_for_peer(dest, source_addr), source_addr) do
        {:ok, packet} ->
          data = to_client(packet, source_addr, dest.peer_to_channel, dest.client_socket)
          ClientSocket.send(dest.client_socket, data)
          Bytes.add_in(dest.pid, byte_size(data))
          maybe_touch(dest.pid, dest.tuple5, src_ip, Map.get(dest.peer_to_channel, source_addr))
          :ok

        :drop ->
          :drop
      end
    end
  end

  defp maybe_touch(pid, tuple5, peer_ip, channel)
       when is_pid(pid) and pid != self() and is_tuple(peer_ip) do
    if Permissions.due_refresh?(tuple5, peer_ip, @touch_interval_ms) do
      Permissions.grant(tuple5, peer_ip)
      Client.touch(pid, peer_ip, channel)
    end
  end

  defp maybe_touch(_, _, _, _), do: :ok

  defp source_relay_address(socket, src_relay) do
    case Store.lookup_sock(socket) do
      {:ok, %{address: address}} when is_tuple(address) -> address
      _ -> src_relay
    end
  end

  defp framing_for_peer(dest, peer_address) do
    if Map.has_key?(dest.peer_to_channel, peer_address),
      do: :channel_data,
      else: :data_indication
  end

  defp tuple5_key(meta) do
    [
      {:ca, meta.client_ip},
      {:cp, meta.client_port},
      {:sa, Tuple5.turn_server_ip(meta.server_ip)},
      {:sp, meta.server_port},
      {:proto, :_}
    ]
  end

  defp format_channel_data(channel_number, len, packet, :stream) do
    pad = rem(4 - rem(len, 4), 4)
    <<channel_number::16, len::16, packet::binary, 0::size(pad * 8)>>
  end

  defp format_channel_data(channel_number, len, packet, :datagram) do
    <<channel_number::16, len::16, packet::binary>>
  end

  defp plugin_egress(tuple5, payload, framing, peer_address, channel) do
    if plugins_enabled?() do
      Dispatch.egress(tuple5, payload, framing, peer_address, channel)
    else
      {:ok, payload}
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

  defp slim_send_attrs(attrs, tid), do: slim_send_attrs(attrs, tid, nil, nil)

  defp slim_send_attrs(<<>>, _tid, peer, data) do
    if is_tuple(peer) and is_binary(data), do: {:ok, peer, data}, else: :error
  end

  defp slim_send_attrs(
         <<type::16, len::16, rest::binary>>,
         tid,
         peer,
         data
       ) do
    padded = pad_attribute(len)
    <<value::binary-size(^len), _pad::binary-size(^padded), tail::binary>> = rest

    {peer, data} =
      case type do
        @attr_xor_peer -> {decode_xor_peer(value, tid), data}
        @attr_data -> {peer, value}
        @attr_fingerprint -> {peer, data}
        _ -> {peer, data}
      end

    slim_send_attrs(tail, tid, peer, data)
  end

  defp slim_send_attrs(_, _tid, _peer, _data), do: :error

  defp pad_attribute(len), do: rem(4 - rem(len, 4), 4)

  defp decode_xor_peer(<<0, 1, xport::16, xaddr::32>>, _tid) do
    port = bxor(xport, bsr(@magic_cookie, 16))
    <<i0, i1, i2, i3>> = <<bxor(xaddr, @magic_cookie)::32>>
    {{i0, i1, i2, i3}, port}
  end

  defp decode_xor_peer(<<0, 2, xport::16, xaddr::128>>, tid) do
    port = bxor(xport, bsr(@magic_cookie, 16))

    <<i0::16, i1::16, i2::16, i3::16, i4::16, i5::16, i6::16, i7::16>> =
      <<bxor(xaddr, bor(bsl(@magic_cookie, 96), tid))::128>>

    {{i0, i1, i2, i3, i4, i5, i6, i7}, port}
  end

  defp require_perms? do
    case Application.get_env(:xturn, :permissions) do
      %{required: required} -> required
      _ -> true
    end
  end
end
