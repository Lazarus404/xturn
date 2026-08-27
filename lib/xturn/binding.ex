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

defmodule Xirsys.XTurn.Binding do
  @moduledoc """
  Handles STUN Binding requests (client address discovery).

  ## What problem this solves

  Before allocating a relay, a client often needs to learn its public IP and
  port as seen by the server (reflexive address). A Binding request asks the
  server to echo that mapping. With dual-homed listen and RFC 5780 attributes,
  the server can also advertise alternate addresses and honor CHANGE-REQUEST so
  ICE can classify NAT behavior.

  ## Internal note

  Invoked from `Pipeline.do_request/1`; not a public operator API.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (Binding, XOR-MAPPED-ADDRESS)
  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (CHANGE-REQUEST, OTHER-ADDRESS, RESPONSE-ORIGIN)
  - [RFC 3489](https://www.rfc-editor.org/rfc/rfc3489) (classic Binding when `classic: true`)
  """

  alias XSockets.Transport.UDP
  alias Xirsys.XTurn.{Conn, DualIp}

  @change_request_type DualIp.change_request_type()

  @doc """
  Processes a Binding request and attaches a `%Conn{}.response`.

  Handles modern (RFC 5389/5780) and classic (RFC 3489) binding forms.
  Sets `reply_from` / `reply_to` when CHANGE-REQUEST or RESPONSE-PORT apply.
  """
  @spec process(Conn.t()) :: Conn.t()
  def process(%Conn{} = conn) do
    case conn.decoded_message do
      %{classic: true} ->
        process_classic(conn)

      %{class: :request, method: :binding} ->
        attrs = conn.decoded_message.attrs || %{}
        transport = conn.client_socket && conn.client_socket.transport

        cond do
          Map.has_key?(attrs, :padding) and Map.has_key?(attrs, :response_port) ->
            Conn.response(conn, 400, "Bad Request")

          Map.has_key?(attrs, :change_request) and transport != UDP ->
            unknown_attr(conn, [@change_request_type])

          Map.has_key?(attrs, :change_request) and not DualIp.armed?() ->
            unknown_attr(conn, [@change_request_type])

          true ->
            process_modern(conn, attrs, transport)
        end

      _ ->
        conn
    end
  end

  defp process_classic(%Conn{decoded_message: %{attrs: attrs}} = conn) do
    cond do
      Map.has_key?(attrs, :response_address) or Map.has_key?(attrs, :change_request) ->
        unknown_attr(conn, forbidden_classic_types(attrs))

      true ->
        mapped = {conn.client_ip, conn.client_port}

        resp = Conn.response(conn, :success, %{mapped_address: mapped})
        %Conn{resp | reply_to: {conn.client_ip, conn.client_port}}
    end
  end

  defp process_modern(conn, attrs, transport) do
    da = conn.server_ip
    dp = conn.server_port

    case reply_endpoint(conn, attrs, da, dp, transport) do
      {:ok, reply_from, reply_origin} ->
        dest = reply_destination(conn, attrs)
        success_attrs = success_attrs(conn, reply_origin)

        %Conn{
          Conn.response(conn, :success, success_attrs)
          | reply_from: reply_from,
            reply_to: dest
        }

      :error ->
        unknown_attr(conn, [@change_request_type])
    end
  end

  defp reply_endpoint(conn, attrs, da, dp, UDP) do
    if Map.has_key?(attrs, :change_request) do
      case DualIp.reply_from(da, dp, attrs.change_request) do
        {:ok, entry, origin} -> {:ok, entry, origin}
        :error -> :error
      end
    else
      {:ok, default_reply_from(conn), {da, dp}}
    end
  end

  defp reply_endpoint(conn, _attrs, da, dp, _transport) do
    {:ok, default_reply_from(conn), {da, dp}}
  end

  defp default_reply_from(%Conn{client_socket: %{transport: transport, socket: socket}}),
    do: {transport, socket}

  defp default_reply_from(_), do: nil

  defp reply_destination(conn, attrs) do
    case Map.get(attrs, :response_port) do
      <<port::16, _::binary>> when is_integer(port) ->
        {conn.client_ip, port}

      port when is_integer(port) ->
        {conn.client_ip, port}

      _ ->
        {conn.client_ip, conn.client_port}
    end
  end

  defp success_attrs(conn, {src_ip, src_port}) do
    mapped = {conn.client_ip, conn.client_port}
    da = conn.server_ip

    base = %{
      xor_mapped_address: mapped,
      mapped_address: mapped,
      response_origin: {src_ip, src_port}
    }

    if other = DualIp.other_address(da) do
      Map.put(base, :other_address, other)
    else
      base
    end
  end

  defp forbidden_classic_types(attrs) do
    []
    |> then(fn acc -> if Map.has_key?(attrs, :change_request), do: [@change_request_type | acc], else: acc end)
    |> then(fn acc -> if Map.has_key?(attrs, :response_address), do: [0x0002 | acc], else: acc end)
  end

  defp unknown_attr(conn, types) do
    padded =
      types
      |> Enum.reduce(<<>>, fn type, acc -> acc <> <<type::16>> end)
      |> pad_unknown_attributes()

    conn = Conn.response(conn, 420, "Unknown Attribute")
    turn = conn.decoded_message
    %Conn{conn | decoded_message: %{turn | attrs: Map.put(turn.attrs, :unknown_attributes, padded)}}
  end

  defp pad_unknown_attributes(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      n -> bin <> :binary.copy(<<0>>, 4 - n)
    end
  end
end
