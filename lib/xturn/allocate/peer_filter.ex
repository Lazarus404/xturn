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

defmodule Xirsys.XTurn.PeerFilter do
  @moduledoc """
  Validates XOR-PEER-ADDRESS for CreatePermission and ChannelBind.

  ## What problem this solves

  Clients name peer endpoints when creating permissions or binding channels. The
  server must reject addresses that would relay to the wrong place (wildcards,
  multicast, the TURN listener ports, or disallowed same-IP cases) while still
  allowing hairpin to other ports on the advertised server address.

  ## Internal note

  Called from TURN action handlers; returns `forbidden?/3` boolean.

  ## RFCs

  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (pt.9 peer address restrictions)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (CreatePermission, ChannelBind)
  """

  alias XSockets.Config

  @doc """
  Returns whether a peer address must be rejected for permission or channel bind.

  Malformed or non-tuple peers return `true`.

  ## Examples

      iex> Xirsys.XTurn.PeerFilter.forbidden?({{0, 0, 0, 0}, 1234})
      true

      iex> Xirsys.XTurn.PeerFilter.forbidden?({{224, 0, 0, 1}, 1234})
      true

      iex> Xirsys.XTurn.PeerFilter.forbidden?({{203, 0, 113, 50}, 50000}, {203, 0, 113, 50}, [])
      true

      iex> Xirsys.XTurn.PeerFilter.forbidden?({{0x2001, 0, 0, 0, 0, 0, 0, 1}, 1234}, nil, [8])
      true

      iex> Xirsys.XTurn.PeerFilter.forbidden?(:not_a_peer)
      true
  """
  def forbidden?(peer, client_ip \\ nil, active_families \\ [])

  def forbidden?({ip, port}, client_ip, active_families)
      when is_tuple(ip) and is_integer(port) do
    cond do
      ip in [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}, {255, 255, 255, 255}] -> true
      multicast_v4?(ip) -> true
      8 in active_families and teredo_or_6to4?(ip) -> true
      turn_listener?(ip, port) -> true
      client_self?(ip, client_ip) -> true
      true -> false
    end
  end

  def forbidden?(_, _, _), do: true

  # RFC 8656 9 MAY refuse the TURN server's own addresses - the listeners,
  # not every port. Other ports on server_ip are XOR-RELAYED-ADDRESS hairpins.
  defp turn_listener?(ip, port), do: advertised?(ip) and port in listener_ports()

  defp advertised?(ip), do: ip == Config.server_ip() or ip == Config.server_ip6()

  defp listener_ports do
    listen = Application.get_env(:xturn, :listen, [])
    Enum.uniq([3478, 5349 | Enum.map(listen, &elem(&1, 2))])
  end

  # Don't treat "peer IP == client IP" as forbidden when that IP is the TURN
  # advertised address: same-host WebRTC (iceTransportPolicy=relay) hairpins.
  defp client_self?(ip, client_ip) when not is_nil(client_ip) and ip == client_ip,
    do: not advertised?(ip)

  defp client_self?(_, _), do: false

  defp teredo_or_6to4?({0x2001, 0, _, _, _, _, _, _}), do: true
  defp teredo_or_6to4?({0x2002, _, _, _, _, _, _, _}), do: true
  defp teredo_or_6to4?(_), do: false

  defp multicast_v4?({a, _, _, _}) when a >= 224 and a <= 239, do: true
  defp multicast_v4?(_), do: false
end
