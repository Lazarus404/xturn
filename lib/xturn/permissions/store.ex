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

defmodule Xirsys.XTurn.Permissions.Store do
  @moduledoc """
  ETS-backed CREATE PERMISSION allowlist keyed by allocation 5-tuple and peer IP.

  ## What problem this solves

  Relay traffic to a peer is denied unless that peer's IP was granted via
  CreatePermission. This table records allowed peers and timestamps so the
  media and relay ingress paths can check permissions in O(1) without calling
  into the allocation GenServer on every packet.

  Each entry is `{{normalized_tuple5, peer_ip}, monotonic_ms}`. The `:proto`
  field is wildcarded so permissions match the allocation regardless of
  control transport.

  ## Internal

  Runtime infrastructure; written by CreatePermission / allocation workers,
  read by `DataPlane` and `RelayIngress.Worker`.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - permissions (pt.8, pt.9)
  """

  alias Xirsys.XTurn.Tuple5, as: T5

  @doc "Creates the public permissions ETS table if it does not exist."
  def init do
    if :ets.whereis(__MODULE__) == :undefined do
      :ets.new(__MODULE__, [:named_table, :public, :set, read_concurrency: true])
    end

    :ok
  end

  @doc "Grants relay permission from `tuple5` to `peer_ip`. Returns `:ok`."
  def grant(tuple5, peer_ip) when is_tuple(peer_ip) do
    :ets.insert(__MODULE__, {{normalize(tuple5), peer_ip}, System.monotonic_time(:millisecond)})
    :ok
  end

  @doc "Returns whether `peer_ip` may send traffic to the allocation identified by `tuple5`."
  def allowed?(tuple5, peer_ip) do
    :ets.member(__MODULE__, {normalize(tuple5), peer_ip})
  end

  @doc """
  Returns true when permission is missing or last granted at least `min_age_ms` ago.

  Used to throttle `Client.touch/3` on the media path. Default interval is 60s.
  """
  def due_refresh?(tuple5, peer_ip, min_age_ms \\ 60_000) do
    key = {normalize(tuple5), peer_ip}
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(__MODULE__, key) do
      [{^key, ts}] when is_integer(ts) and now - ts < min_age_ms -> false
      _ -> true
    end
  end

  @doc false
  def stamp(tuple5, peer_ip, monotonic_ms) when is_integer(monotonic_ms) do
    :ets.insert(__MODULE__, {{normalize(tuple5), peer_ip}, monotonic_ms})
    :ok
  end

  @doc "Revokes permission for a single peer on `tuple5`. Returns `:ok`."
  def revoke(tuple5, peer_ip) do
    :ets.delete(__MODULE__, {normalize(tuple5), peer_ip})
    :ok
  end

  @doc "Revokes every peer permission for `tuple5`. Returns `:ok`."
  def revoke_all(tuple5) do
    :ets.match_delete(__MODULE__, {{normalize(tuple5), :_}, :_})
    :ets.match_delete(__MODULE__, {{normalize(tuple5), :_}})
    :ok
  end

  defp normalize(%T5{} = tuple5), do: normalize(T5.to_map(tuple5))
  defp normalize(tuple5) when is_list(tuple5) do
    map = Map.new(tuple5)

    [
      {:ca, map[:ca]},
      {:cp, map[:cp]},
      {:sa, map[:sa]},
      {:sp, map[:sp]},
      {:proto, :_}
    ]
  end
end
