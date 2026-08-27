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

defmodule Xirsys.XTurn.Actions.CreatePerm do
  @moduledoc """
  Pipeline action for TURN **CreatePermission** requests.

  ## What problem this solves

  Before relayed traffic may flow to a peer, the client must authorize that
  peer's IP on its allocation. **CreatePermission** adds those peer IPs to the
  allowlist checked on the media and relay ingress paths.

  Runs in the `@createpermission` chain after `Authenticates`.

  ## Internal

  Pipeline action only; not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - CreatePermission (pt.9)
  """
  require Logger
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.{PeerFilter, RelayFamily}
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn

  @doc """
  Adds peer IP permissions on the caller's allocation.

  Returns conn with a success response, or 400/403/437/443 on error.
  """
  def process(%Conn{decoded_message: %{attrs: attrs}} = conn) do
    Logger.debug("creating a permission #{inspect(conn.decoded_message)}")
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))
    peers = peers_from_attrs(attrs)

    cond do
      peers == [] ->
        Logger.debug("no permissions sent")
        Conn.response(conn, 400, "Bad Request")

      true ->
        case Store.lookup(tuple5) do
          {:ok, [client, _peer_address, _, _]} ->
            families = AllocateClient.active_families(client)

            cond do
              Enum.any?(peers, &PeerFilter.forbidden?(&1, conn.client_ip, families)) ->
                Conn.response(conn, 403, "Forbidden")

              Enum.any?(peers, &(not RelayFamily.peer_allowed?(&1, families))) ->
                Conn.response(conn, 443, "Peer Address Family Mismatch")

              true ->
                Enum.each(peers, fn {peer_ip, _} ->
                  Logger.debug("createperm #{inspect(client)}, #{inspect(peer_ip)}")
                  AllocateClient.add_permissions(client, peer_ip)
                end)

                Conn.response(conn, :success)
            end

          {:error, :not_found} ->
            Logger.debug("client does not exist #{inspect(tuple5)} (createperm)")
            Conn.response(conn, 437, "Allocation Mismatch")
        end
    end
  end

  defp peers_from_attrs(attrs) do
    case Map.get(attrs, :xor_peer_address) do
      nil -> []
      list when is_list(list) -> list
      peer -> [peer]
    end
  end
end
