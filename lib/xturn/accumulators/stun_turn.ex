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

defmodule Xirsys.XTurn.Accumulators.StunTurn do
  @moduledoc """
  STUN/TURN framing accumulator for one client connection.

  ## What problem this solves

  TURN multiplexes STUN messages (first two bits `00`) and ChannelData frames
  (first two bits `01`) on the same socket. This accumulator buffers incoming
  bytes, splits them into complete messages, and strips transport-specific
  ChannelData padding before handing frames to the handler.

  `:framing` selects padding rules:

    * `:stream`   - padding required (TCP/TLS); consumed after each ChannelData
    * `:datagram` - padding optional (UDP/DTLS); unpadded frames are accepted

  Emitted messages never include trailing alignment bytes.

  ## Internal

  Used as the `:accumulator` tier in `SocketPipeline`; not called by
  application code directly.

  ## RFCs

  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - STUN message length and attribute padding (pt.15)
  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - ChannelData format and padding (pt.11, pt.11.5)
  """
  @behaviour XSockets.Accumulator

  @send_msg 0
  @channel_msg 1
  @default_max 1024 * 1024
  @header_size 4

  @impl true
  @doc """
  Accumulator state: `:max_size` (default 1 MiB) and `:framing` (`:stream` or `:datagram`).

  See module doc for ChannelData padding rules per transport.
  """
  def init(opts) do
    %{
      buffer: <<>>,
      max_size: Keyword.get(opts, :max_size, @default_max),
      framing: Keyword.get(opts, :framing, :stream),
      overflow: false
    }
  end

  @impl true
  @doc """
  Appends `chunk` to the internal buffer.

  When the buffer exceeds `:max_size`, oldest bytes are dropped and `:overflow`
  is set; the next `pop/1` returns `{:error, :buffer_overflow, acc}`.
  """
  def push(%{buffer: <<>>} = acc, chunk, _meta) do
    acc = %{acc | buffer: chunk}

    if byte_size(chunk) > acc.max_size do
      trim = byte_size(chunk) - acc.max_size
      <<_drop::binary-size(^trim), rest::binary>> = chunk
      %{acc | buffer: rest, overflow: true}
    else
      acc
    end
  end

  def push(%{buffer: buffer, max_size: max_size} = acc, chunk, _meta) do
    buffer = <<buffer::binary, chunk::binary>>
    acc = %{acc | buffer: buffer}

    if byte_size(buffer) > max_size do
      trim = byte_size(buffer) - max_size
      <<_drop::binary-size(^trim), rest::binary>> = buffer
      %{acc | buffer: rest, overflow: true}
    else
      acc
    end
  end

  @impl true
  @doc """
  Extracts the next complete STUN or ChannelData message from the buffer.

  Returns `{:ok, message, meta, acc}`, `{:more, acc}` when incomplete, or
  `{:error, reason, acc}` on overflow or unknown framing.
  """
  def pop(%{overflow: true} = acc) do
    {:error, :buffer_overflow, %{acc | overflow: false}}
  end

  def pop(%{buffer: buffer} = acc) when byte_size(buffer) < @header_size do
    {:more, acc}
  end

  def pop(%{buffer: buffer, framing: framing} = acc) do
    <<type::2, _::14, body_bytes::16, _rest::binary>> = buffer

    if type != @send_msg and type != @channel_msg do
      {:error, :unknown_framing, %{acc | buffer: <<>>}}
    else
      take(acc, buffer, message_size(type, body_bytes), consumed_size(type, body_bytes, framing))
    end
  end

  defp take(acc, buffer, message_bytes, consumed) when byte_size(buffer) >= consumed do
    padding = consumed - message_bytes

    <<message::binary-size(^message_bytes), _padding::binary-size(^padding), rest::binary>> =
      buffer

    {:ok, message, %{}, %{acc | buffer: rest}}
  end

  defp take(acc, _buffer, _message, _consumed), do: {:more, acc}

  # A STUN message's length field already accounts for its attributes' internal
  # padding (RFC 5389, Section 15), so there is never trailing padding to skip.
  defp message_size(@send_msg, body_bytes), do: body_bytes + 20
  defp message_size(@channel_msg, body_bytes), do: @header_size + body_bytes

  defp consumed_size(@send_msg, body_bytes, _framing), do: body_bytes + 20
  defp consumed_size(@channel_msg, body_bytes, :stream), do: @header_size + pad_to_4(body_bytes)
  defp consumed_size(@channel_msg, body_bytes, _datagram), do: @header_size + body_bytes

  defp pad_to_4(n) when n <= 0, do: 0
  defp pad_to_4(n), do: Bitwise.band(n + 3, -4)
end
