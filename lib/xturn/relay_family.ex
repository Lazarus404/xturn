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

defmodule Xirsys.XTurn.RelayFamily do
  @moduledoc """
  Gates peer and refresh operations by active relay address family.

  ## What problem this solves

  A dual-stack allocation may hold both IPv4 and IPv6 relay sockets. CreatePermission
  and ChannelBind must reject peers whose IP version has no active relay path.
  Refresh with REQUESTED-ADDRESS-FAMILY must only extend lifetimes for families
  that still exist on the allocation.

  ## Internal note

  Called from TURN action modules during permission, channel, and refresh handling.

  ## RFCs

  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (multi-family allocations and refresh)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (permissions and channels)
  """

  alias Xirsys.XTurn.AddressFamily

  @doc """
  Returns whether a peer address matches one of the allocation's active families.

  ## Examples

      iex> Xirsys.XTurn.RelayFamily.peer_allowed?({{127, 0, 0, 1}, 1234}, [4])
      true

      iex> Xirsys.XTurn.RelayFamily.peer_allowed?({{127, 0, 0, 1}, 1234}, [8])
      false

      iex> Xirsys.XTurn.RelayFamily.peer_allowed?({{127, 0, 0, 1}, 1234}, :invalid)
      false
  """
  def peer_allowed?(peer_address, active_families) when is_list(active_families) do
    fam = AddressFamily.family_of(elem(peer_address, 0))
    fam != nil and fam in active_families
  end

  def peer_allowed?(_peer_address, _), do: false

  @doc """
  Returns whether a REQUESTED-ADDRESS-FAMILY value is still active on the allocation.

  ## Examples

      iex> alias Xirsys.XTurn.{AddressFamily, RelayFamily}
      iex> RelayFamily.refresh_family_active?(AddressFamily.ipv4(), [4, 8])
      true

      iex> Xirsys.XTurn.RelayFamily.refresh_family_active?(Xirsys.XTurn.AddressFamily.ipv6(), [4])
      false
  """
  def refresh_family_active?(raf, active_families) when is_list(active_families) do
    cond do
      raf == AddressFamily.ipv4() -> 4 in active_families
      raf == AddressFamily.ipv6() -> 8 in active_families
      true -> false
    end
  end

  def refresh_family_active?(_, _), do: false
end
