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

defmodule Xirsys.XTurn.Channels.Store do
  @moduledoc """
  ETS-backed store of TURN channel bindings (client -> peer direction).

  ## What problem this solves

  When a client sends ChannelData, the server must map the channel number to
  the bound peer quickly. This table stores `{allocation 5-tuple, channel_number}
  -> {worker pid, peer address, ...}` for O(1) lookup on the media path.

  Keys normalize the allocation `:proto` field so lookups match regardless of
  UDP vs TCP on the control socket. Peer -> client relay uses `RelayIngress`
  and `Allocate.Store.lookup_sock/1` instead.

  ## Internal

  Runtime infrastructure; populated by allocation workers on ChannelBind and
  read by `DataPlane` / `Actions.ChannelData`.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - channels and ChannelBind (pt.11)
  """
  @vsn "0"

  alias Xirsys.XTurn.Tuple5, as: T5

  @doc "Creates the public channel-bindings ETS table."
  def init(),
    do: Exts.new(__MODULE__, access: :public)

  @doc "Registers (or overwrites) the channel binding for `{tuple5, cid}`."
  def insert(cid, pid, {_ip, _port} = peer_address, %T5{} = tuple5, socket \\ nil, relayed_address \\ nil)
      when is_integer(cid) do
    :ets.insert(__MODULE__, {{normalize(tuple5), cid}, {pid, peer_address, socket, relayed_address}})
    :ok
  end

  @doc """
  O(1) lookup of the channel `cid` bound by the allocation identified by
  `tuple5`. Returns `{:ok, {pid, peer_address, socket}}` or
  `{:error, :not_found}`.
  """
  def lookup(cid, tuple5) when is_integer(cid) do
    case :ets.lookup(__MODULE__, {normalize(tuple5), cid}) do
      [{_key, {pid, peer_address, socket, relayed_address}}] ->
        {:ok, {pid, peer_address, socket, relayed_address}}

      [] ->
        {:error, :not_found}
    end
  end

  @doc "Returns `true` when channel `cid` is bound on the allocation identified by `tuple5`."
  def exists?(cid, tuple5), do: match?({:ok, _}, lookup(cid, tuple5))

  @doc "Deletes a single channel binding, scoped to the allocation identified by `tuple5`."
  def delete(cid, tuple5) when is_integer(cid),
    do: :ets.delete(__MODULE__, {normalize(tuple5), cid})

  @doc "Deletes every channel binding belonging to a given allocation."
  def delete_all(tuple5),
    do: :ets.match_delete(__MODULE__, {{normalize(tuple5), :_}, :_})

  # Reduces any tuple5 (struct or Tuple5.to_map/1 list, whatever protocol it
  # carries) down to the canonical key shape used throughout this table.
  defp normalize(%T5{} = tuple5), do: normalize(T5.to_map(tuple5))

  defp normalize([{:ca, ca}, {:cp, cp}, {:sa, sa}, {:sp, sp}, {:proto, _}]),
    do: [{:ca, ca}, {:cp, cp}, {:sa, sa}, {:sp, sp}, {:proto, :_}]
end
