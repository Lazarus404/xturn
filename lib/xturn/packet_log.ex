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

defmodule Xirsys.XTurn.PacketLog do
  @moduledoc """
  Structured logging of raw STUN/TURN datagrams exchanged with clients.

  ## What problem this solves

  Protocol-level debugging (401/438 auth loops, missing attributes, transaction
  correlation) needs a timeline of every datagram in both directions without
  enabling full packet capture. Each line includes direction, peer, byte count,
  framing hint, and a hex dump. Lines go to `Logger.debug/1` and a dedicated
  file via `PacketLog.Writer` so they can be grepped apart from general logs.

  Toggle with `:packet_log_enabled` (default `true`). Write failures never crash
  relay traffic.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (STUN framing logged)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN methods and
    ChannelData framing logged)
  """
  require Logger

  alias Xirsys.XTurn.PacketLog.Writer

  @doc "Logs a raw datagram received from a client."
  @spec incoming(binary(), :inet.ip_address() | nil, :inet.port_number() | nil) :: :ok
  def incoming(bin, ip, port) when is_binary(bin), do: write(:in, bin, ip, port)

  @doc "Logs a raw datagram (STUN/TURN reply) sent to a client."
  @spec outgoing(iodata(), :inet.ip_address() | nil, :inet.port_number() | nil) :: :ok
  def outgoing(iodata, ip, port), do: write(:out, IO.iodata_to_binary(iodata), ip, port)

  defp write(dir, bin, ip, port) do
    if Application.get_env(:xturn, :packet_log_enabled, true) do
      line = format(dir, bin, ip, port)
      Logger.debug(line)
      Writer.append(line)
    end

    :ok
  rescue
    error ->
      Logger.debug("[PACKET] failed to log #{dir} packet: #{inspect(error)}")
      :ok
  end

  defp format(dir, bin, ip, port) do
    "[PACKET] dir=#{dir} peer=#{format_ip(ip)}:#{inspect(port)} bytes=#{byte_size(bin)} " <>
      "#{describe(bin)} hex=#{hex_dump(bin)}"
  end

  defp describe(<<0::2, _::14, _rest::binary>>), do: "stun_framing"

  defp describe(<<1::2, num::14, length::16, _rest::binary>>),
    do: "channeldata number=#{num} length=#{length}"

  defp describe(_bin), do: "unknown_framing"

  defp hex_dump(bin) do
    for <<byte <- bin>>, into: "" do
      byte |> Integer.to_string(16) |> String.pad_leading(2, "0") |> Kernel.<>(" ")
    end
    |> String.trim_trailing()
  end

  defp format_ip(nil), do: "nil"

  defp format_ip(ip) when is_tuple(ip) do
    case :inet.ntoa(ip) do
      {:error, _} -> inspect(ip)
      charlist -> to_string(charlist)
    end
  end

  defp format_ip(ip), do: inspect(ip)
end
