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

defmodule Xirsys.XTurn.Tuple5 do
  @moduledoc """
  Five-tuple identity for a TURN allocation on this server.

  ## What problem this solves

  Refresh, ChannelBind, and CreatePermission must locate the existing allocation
  for a client without requiring the original Allocate transaction id. The
  five-tuple (client IP/port, server IP/port, requested transport) keys ETS
  lookups in `Allocate.Store`.

  ## Internal note

  `:proto` may be `:_` to wildcard transport on refresh-style lookups.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (five-tuple allocation identity)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TCP REQUESTED-TRANSPORT)
  """
  alias XSockets.Config
  alias Xirsys.XTurn.{Conn, Tuple5}

  @vsn "0"

  @typedoc """
  Five-tuple allocation identity (`t`).

  ## Fields

  - `:client_address`, `:client_port`, `:server_address`, `:server_port`, `:protocol`
  """
  @type t :: %__MODULE__{
          client_address: :inet.ip_address() | nil,
          client_port: pos_integer() | nil,
          server_address: :inet.ip_address() | nil,
          server_port: pos_integer() | nil,
          protocol: binary() | :udp | :tcp | :_
        }
  defstruct client_address: nil,
            client_port: nil,
            server_address: nil,
            server_port: nil,
            protocol: :udp


  @doc """
  Builds a 5-tuple for the current connection. `proto` is either the requested
  transport binary from an Allocate request, or `:_` - an ETS match wildcard used
  by Refresh/ChannelBind/CreatePermission, which look up an existing allocation by
  client/server IP:port only, regardless of the protocol it was originally
  allocated with (see `Xirsys.XTurn.Allocate.Store.lookup/1`).
  """
  def create(%Conn{} = conn, proto) when is_binary(proto) or proto == :_ do
    %Tuple5{
      client_address: conn.client_ip,
      client_port: conn.client_port,
      server_address: turn_server_ip(conn),
      server_port: conn.server_port,
      protocol: proto
    }
  end

  @doc false
  def turn_server_ip(%Conn{server_ip: server_ip}), do: turn_server_ip(server_ip)

  @doc false
  def turn_server_ip(server_ip) do
    if unspecified?(server_ip), do: Config.server_ip(), else: server_ip
  end

  defp unspecified?(nil), do: true
  defp unspecified?({0, 0, 0, 0}), do: true
  defp unspecified?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp unspecified?(_), do: false

  @doc """
  Converts a `%Tuple5{}` into an ETS-friendly keyword list (`ca`, `cp`, `sa`, `sp`, `proto`).

  ## Examples

      iex> alias Xirsys.XTurn.Tuple5
      iex> t = %Tuple5{
      ...>   client_address: {1, 2, 3, 4},
      ...>   client_port: 1,
      ...>   server_address: {5, 6, 7, 8},
      ...>   server_port: 2,
      ...>   protocol: :udp
      ...> }
      iex> Tuple5.to_map(t)
      [ca: {1, 2, 3, 4}, cp: 1, sa: {5, 6, 7, 8}, sp: 2, proto: :udp]
  """
  def to_map(%Tuple5{
        client_address: ca,
        client_port: cp,
        server_address: sa,
        server_port: sp,
        protocol: proto
      }) do
    [{:ca, ca}, {:cp, cp}, {:sa, sa}, {:sp, sp}, {:proto, proto}]
  end
end
