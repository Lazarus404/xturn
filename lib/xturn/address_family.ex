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

defmodule Xirsys.XTurn.AddressFamily do
  @moduledoc """
  IPv4/IPv6 address-family constants for TURN Allocate and Refresh.

  ## What problem this solves

  Dual-stack TURN clients request relay addresses in a specific IP version via
  REQUESTED-ADDRESS-FAMILY and related attributes. The server must compare those
  four-byte values, map Erlang IP tuples to internal family ids (`4` / `8`), and
  encode ADDRESS-ERROR-CODE when a family cannot be honored.

  ## Internal note

  Used by allocation and action handlers; not an operator API.

  ## RFCs

  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (REQUESTED-ADDRESS-FAMILY, ADDITIONAL-ADDRESS-FAMILY, ADDRESS-ERROR-CODE)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (base TURN allocation)
  """

  @ipv4 <<0x01, 0, 0, 0>>
  @ipv6 <<0x02, 0, 0, 0>>

  @doc """
  Four-byte REQUESTED-ADDRESS-FAMILY value for IPv4 (`0x01`).
  """
  def ipv4, do: @ipv4

  @doc """
  Four-byte REQUESTED-ADDRESS-FAMILY value for IPv6 (`0x02`).
  """
  def ipv6, do: @ipv6

  @doc """
  Maps an IP tuple to relay family `4`, `8`, or `nil` when unrecognized.

  ## Examples

      iex> Xirsys.XTurn.AddressFamily.family_of({127, 0, 0, 1})
      4

      iex> Xirsys.XTurn.AddressFamily.family_of({0, 0, 0, 0, 0, 0, 0, 1})
      8

      iex> Xirsys.XTurn.AddressFamily.family_of(:not_an_address)
      nil
  """
  def family_of({a, _, _, _}) when is_integer(a) and a < 256, do: 4
  def family_of({_, _, _, _, _, _, _, _}), do: 8
  def family_of(_), do: nil

  @doc """
  Returns whether Allocate attrs request an IPv6 relay address.

  ## Examples

      iex> alias Xirsys.XTurn.AddressFamily
      iex> AddressFamily.ipv6_requested?(%{requested_address_type: AddressFamily.ipv6()})
      true

      iex> Xirsys.XTurn.AddressFamily.ipv6_requested?(%{})
      false
  """
  def ipv6_requested?(attrs), do: Map.get(attrs, :requested_address_type) == @ipv6

  @doc """
  Returns whether attrs carry an ADDITIONAL-ADDRESS-FAMILY of IPv6.

  Used for dual-stack Allocate requests per RFC 8656.

  ## Parameters

    * `attrs` - decoded STUN attribute map (may include `:additional_address_family`)
  """
  def dual_additional?(attrs), do: Map.get(attrs, :additional_address_family) == @ipv6

  @doc """
  Builds an ADDRESS-ERROR-CODE attribute binary.

  ## Parameters

    * `family_byte` - address-family byte (e.g. `1` for IPv4)
    * `err_no` - three-digit STUN error number (class * 100 + number)
    * `reason` - UTF-8 reason phrase
  """
  def address_error_code(family_byte, err_no, reason) when is_binary(reason) do
    class = div(err_no, 100)
    number = rem(err_no, 100)
    <<family_byte::8, 0::13, class::3, number::8, reason::binary>>
  end
end
