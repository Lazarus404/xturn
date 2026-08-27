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

defmodule Xirsys.XTurn.DualIp do
  @moduledoc """
  Dual-homed listen helpers for NAT behavior discovery.

  ## What problem this solves

  ICE agents test whether their NAT mapping depends on destination IP or port by
  sending Binding requests with CHANGE-REQUEST and reading OTHER-ADDRESS in the
  response. That requires the server to listen on two addresses (and often two
  ports) and reply from the alternate socket when asked.

  This module decides when that mode is fully configured (`armed?/0`) and maps
  CHANGE-REQUEST flags to a registered `{transport, socket}` via `ListenRegistry`.

  ## Internal note

  Enabled via application env (`:other_ip`, `:other_port`, concrete `:server_ip`);
  operators configure listen tuples, not these functions.

  ## RFCs

  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (CHANGE-REQUEST, OTHER-ADDRESS)
  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (Binding attribute types)
  """

  alias XSockets.Config
  alias Xirsys.XTurn.ListenRegistry

  @change_request_type 0x0003

  @doc """
  Returns the STUN CHANGE-REQUEST attribute type (`0x0003`).

  ## Examples

      iex> Xirsys.XTurn.DualIp.change_request_type()
      0x0003
  """
  def change_request_type(), do: @change_request_type

  @doc """
  Returns whether dual-IP NAT discovery is fully armed.

  True only when `endpoints/0` succeeds and `ListenRegistry` holds sockets for
  all four `(A1,P1)`, `(A2,P2)`, `(A1,P2)`, `(A2,P1)` combinations.

  ## Examples

      iex> is_boolean(Xirsys.XTurn.DualIp.armed?())
      true
  """
  @spec armed?() :: boolean()
  def armed?() do
    case endpoints() do
      {:ok, a1, a2, p1, p2} ->
        [{a1, p1}, {a2, p2}, {a1, p2}, {a2, p1}]
        |> Enum.all?(fn ep -> match?({:ok, _}, ListenRegistry.lookup(ep)) end)

      :error ->
        false
    end
  end

  @doc """
  Returns OTHER-ADDRESS `{ip, port}` for Binding success when dual-IP is configured.

  Given the destination address `da` the client used, returns the alternate
  server address for the OTHER-ADDRESS attribute, or `nil` when not configured.

  ## Examples

      iex> Xirsys.XTurn.DualIp.other_address({127, 0, 0, 1})
      nil
  """
  @spec other_address(:inet.ip_address()) :: {:inet.ip_address(), :inet.port_number()} | nil
  def other_address(da) do
    case endpoints() do
      {:ok, a1, a2, _p1, p2} ->
        if da == a1, do: {a2, p2}, else: {a1, stun_port()}

      :error ->
        nil
    end
  end

  @doc """
  Resolves the socket and source address for a CHANGE-REQUEST reply.

  `change_req` is a list of flags (`:ip`, `:port`) from the decoded attribute.
  Returns `{:ok, {transport, socket}, {src_ip, src_port}}` when the alternate
  endpoint is registered, otherwise `:error`.

  ## Examples

      iex> Xirsys.XTurn.DualIp.reply_from({127, 0, 0, 1}, 3478, [:ip])
      :error
  """
  @spec reply_from(:inet.ip_address(), :inet.port_number(), [atom()]) ::
          {:ok, {module(), term()}, {:inet.ip_address(), :inet.port_number()}} | :error
  def reply_from(da, dp, change_req) do
    case endpoints() do
      {:ok, a1, a2, p1, p2} ->
        ca = if da == a1, do: a2, else: a1
        cp = if dp == p1, do: p2, else: p1
        flags = List.wrap(change_req)

        src_ip = if :ip in flags, do: ca, else: da
        src_port = if :port in flags, do: cp, else: dp

        case ListenRegistry.lookup({src_ip, src_port}) do
          {:ok, entry} -> {:ok, entry, {src_ip, src_port}}
          :error -> :error
        end

      :error ->
        :error
    end
  end

  @doc """
  Returns primary and alternate listen endpoints when configuration is complete.

  Reads `XSockets.Config.server_ip/0`, `:other_ip`, STUN port, and `:other_port`.
  Returns `{:ok, a1, a2, p1, p2}` or `:error` when any value is missing or wildcard.

  ## Examples

      iex> Xirsys.XTurn.DualIp.endpoints()
      :error
  """
  @spec endpoints() :: {:ok, tuple(), tuple(), pos_integer(), pos_integer()} | :error
  def endpoints() do
    a1 = Config.server_ip()
    a2 = Application.get_env(:xturn, :other_ip)
    p2 = Application.get_env(:xturn, :other_port)
    p1 = stun_port()

    if concrete_ip?(a1) and concrete_ip?(a2) and is_integer(p1) and is_integer(p2) do
      {:ok, a1, a2, p1, p2}
    else
      :error
    end
  end

  defp stun_port(), do: Xirsys.XTurn.ListenConfig.turn_port()

  defp concrete_ip?({0, 0, 0, 0}), do: false
  defp concrete_ip?({0, 0, 0, 0, 0, 0, 0, 0}), do: false
  defp concrete_ip?(_), do: true
end
