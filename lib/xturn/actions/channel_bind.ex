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

defmodule Xirsys.XTurn.Actions.ChannelBind do
  @moduledoc """
  Pipeline action for TURN **ChannelBind** requests.

  ## What problem this solves

  Channel bindings replace Send/Data indications with lighter **ChannelData**
  frames for high-throughput media. **ChannelBind** maps a channel number
  (0x4000-0x7FFE) to a peer on the caller's allocation.

  Runs in the `@channelbind` chain after `Authenticates`.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - ChannelBind (pt.11)
  """
  require Logger
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.{PeerFilter, RelayFamily}
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn

  @doc """
  Binds a channel number to a peer on the caller's allocation.

  Returns conn with a success response, or 400/403/437/443 on error.
  Idempotent retransmits replay cached response attrs.
  """
  def process(%Conn{decoded_message: %{attrs: attrs, transactionid: tid}} = conn) do
    Logger.debug("channelbinding #{inspect(conn.decoded_message)}")

    with true <- Map.has_key?(attrs, :channel_number) and Map.has_key?(attrs, :xor_peer_address),
         <<channel_number::16, _::16>> <- Map.get(attrs, :channel_number),
         true <- channel_number >= 0x4000 and channel_number <= 0x7FFE,
         peer_address when not is_nil(peer_address) <- single_peer(attrs) do
      cond do
        true ->
          tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))

          case Store.lookup(tuple5) do
            {:ok, [client, {_relay_ip, _relay_port}, _, _]} ->
              families = AllocateClient.active_families(client)

              cond do
                PeerFilter.forbidden?(peer_address, conn.client_ip, families) ->
                  Conn.response(conn, 403, "Forbidden")

                not RelayFamily.peer_allowed?(peer_address, families) ->
                  Conn.response(conn, 443, "Peer Address Family Mismatch")

                true ->
                  case AllocateClient.cached_response(client, :channelbind, tid) do
                    nil ->
                      bind_channel(conn, client, channel_number, peer_address, tid)

                    cached ->
                      Conn.response(conn, :success, cached)
                  end
              end

            {:error, :not_found} ->
              Conn.response(conn, 437, "Allocation Mismatch")
          end
      end
    else
      _ ->
        Logger.info("Required attributes not found during channel bind")
        Conn.response(conn, 400, "Bad Request")
    end
  end

  defp bind_channel(conn, client, channel_number, peer_address, tid) do
    case AllocateClient.bind_channel(client, channel_number, peer_address) do
      :ok ->
        AllocateClient.cache_response(client, :channelbind, tid, %{})
        Conn.response(conn, :success)

      {:error, :conflict} ->
        Logger.info(
          "Invalid channel number provided in request - channel number or peer address already in use"
        )

        Conn.response(conn, 400, "Bad Request")
    end
  end

  defp single_peer(attrs) do
    case Map.get(attrs, :xor_peer_address) do
      {_, _} = peer -> peer
      [peer | _] -> peer
      _ -> nil
    end
  end
end
