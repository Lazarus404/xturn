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

defmodule Xirsys.XTurn.StunHelper do
  @moduledoc """
  Encodes STUN indications for peer-to-client relay traffic.

  ## What problem this solves

  When no channel is bound, relayed peer data reaches the client as STUN
  indications (Data, ICMP error, or ConnectionAttempt). These are not
  request/response exchanges on the client socket, so they omit MESSAGE-INTEGRITY
  and FINGERPRINT. Encoding uses [xmedialib](https://github.com/Lazarus404/xmedialib).

  ## Internal note

  Called from `DataPlane` and allocation ICMP handling.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (Data indication)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (ConnectionAttempt indication)
  """

  alias XMediaLib.Stun

  @tid_counter :xturn_data_indication_tid

  @doc """
  Encodes a DATA indication carrying `packet` to `peer_address`.

  Uses a monotonic transaction-id counter so successive indications remain
  distinguishable in packet captures.
  """
  @spec data_indication(binary(), {term(), term()}) :: binary()
  def data_indication(packet, peer_address) do
    encode_data_indication(Stun, packet, peer_address, nil, next_tid())
  end

  @doc """
  Encodes a DATA indication with an embedded ICMP error attribute for `peer_address`.
  """
  @spec icmp_indication({term(), term()}, non_neg_integer(), non_neg_integer(), non_neg_integer()) ::
          binary()
  def icmp_indication(peer_address, type, code, error_data) do
    icmp = <<0::16, type::8, code::8, error_data::32>>
    <<tid::96>> = :crypto.strong_rand_bytes(12)
    encode_data_indication(Stun, <<>>, peer_address, icmp, tid)
  end

  @doc """
  Encodes a CONNECTION-ATTEMPT indication (RFC 6062) for `peer_address`.
  """
  @spec connection_attempt_indication({term(), term()}, binary()) :: binary()
  def connection_attempt_indication(peer_address, connection_id) do
    <<tid::96>> = :crypto.strong_rand_bytes(12)

    stun =
      struct(Stun, %{
        class: :indication,
        method: :connection_attempt,
        transactionid: tid,
        integrity: false,
        fingerprint: false,
        attrs: %{
          xor_peer_address: peer_address,
          connection_id: connection_id
        }
      })

    Stun.encode(stun)
  end

  defp encode_data_indication(stun_mod, packet, peer_address, icmp, tid) do
    attrs =
      %{xor_peer_address: peer_address}
      |> maybe_put_data(packet)
      |> maybe_put_icmp(icmp)

    stun =
      struct(stun_mod, %{
        class: :indication,
        method: :data,
        transactionid: tid,
        integrity: false,
        fingerprint: false,
        attrs: attrs
      })

    apply(stun_mod, :encode, [stun])
  end

  defp maybe_put_data(attrs, <<>>), do: attrs
  defp maybe_put_data(attrs, packet), do: Map.put(attrs, :data, packet)
  defp maybe_put_icmp(attrs, nil), do: attrs
  defp maybe_put_icmp(attrs, icmp), do: Map.put(attrs, :icmp, icmp)

  defp next_tid do
    ref =
      case :persistent_term.get(@tid_counter, nil) do
        nil ->
          ref = :atomics.new(1, signed: false)
          :persistent_term.put(@tid_counter, ref)
          ref

        ref ->
          ref
      end

    :atomics.add_get(ref, 1, 1)
  end
end
