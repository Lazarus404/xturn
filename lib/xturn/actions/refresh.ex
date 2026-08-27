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

defmodule Xirsys.XTurn.Actions.Refresh do
  @moduledoc """
  Pipeline action for TURN **Refresh** requests.

  ## What problem this solves

  TURN allocations expire unless the client extends or explicitly deletes them.
  **Refresh** updates the lifetime timer (or tears down the allocation when
  lifetime is zero), including per-address-family refresh when requested.

  Runs in the `@refresh` chain after `Authenticates`.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - Refresh (pt.7)
  * [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656) - dual-stack refresh
  """
  require Logger
  alias Xirsys.XTurn.AddressFamily
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.RelayFamily
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn

  @default_lifetime 600

  @doc """
  Refreshes or deletes the allocation lifetime, optionally per address family.

  Returns conn with success attrs (lifetime TLV), or 437/443/400 on error.
  Idempotent retransmits replay cached response attrs.
  """
  def process(%Conn{decoded_message: %{attrs: attrs, transactionid: tid}} = conn) do
    Logger.debug("refreshing #{inspect(conn.decoded_message)}")
    val = Map.get(attrs, :lifetime, <<@default_lifetime::32>>)
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))
    raf = Map.get(attrs, :requested_address_type)

    case Store.lookup(tuple5) do
      {:ok, [client, {_relay_ip, _relay_port}, _, _]} ->
        families = AllocateClient.active_families(client)

        cond do
          raf && not RelayFamily.refresh_family_active?(raf, families) ->
            Conn.response(conn, 443, "Peer Address Family Mismatch")

          true ->
            case AllocateClient.cached_response(client, :refresh, tid) do
              nil -> do_refresh(conn, client, val, raf, families, tid)
              cached -> Conn.response(conn, :success, cached)
            end
        end

      {:error, :not_found} ->
        Conn.response(conn, 437, "Allocation Mismatch")
    end
  end

  defp do_refresh(conn, client, <<0::32>>, nil, _families, tid) do
    AllocateClient.refresh(client, 0)
    attrs = %{lifetime: <<0::32>>}
    AllocateClient.cache_response(client, :refresh, tid, attrs)
    Conn.response(conn, :success, attrs)
  end

  defp do_refresh(conn, client, <<0::32>>, raf, _families, tid) do
    family = if raf == AddressFamily.ipv6(), do: 8, else: 4
    lifetime = 0
    GenServer.cast(client, {:refresh_family, family, lifetime})
    attrs = %{lifetime: <<0::32>>}
    AllocateClient.cache_response(client, :refresh, tid, attrs)
    Conn.response(conn, :success, attrs)
  end

  defp do_refresh(conn, client, <<b::32>>, nil, _families, tid) when is_integer(b) do
    b = if b > @default_lifetime, do: @default_lifetime, else: b
    AllocateClient.refresh(client, b)
    attrs = %{lifetime: <<b::32>>}
    AllocateClient.cache_response(client, :refresh, tid, attrs)
    Conn.response(conn, :success, attrs)
  end

  defp do_refresh(conn, client, <<b::32>>, raf, _families, tid) when is_integer(b) do
    b = if b > @default_lifetime, do: @default_lifetime, else: b
    family = if raf == AddressFamily.ipv6(), do: 8, else: 4
    GenServer.cast(client, {:refresh_family, family, b})
    attrs = %{lifetime: <<b::32>>}
    AllocateClient.cache_response(client, :refresh, tid, attrs)
    Conn.response(conn, :success, attrs)
  end

  defp do_refresh(conn, _client, val, _raf, _families, _tid) do
    Logger.info("Bad value #{inspect(val)} in refresh request")
    Conn.response(conn, 400, "Bad Request")
  end
end
