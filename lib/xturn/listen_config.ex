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

defmodule Xirsys.XTurn.ListenConfig do
  @moduledoc """
  Resolves STUN/TURN listen ports and default bind tuples.

  ## What problem this solves

  The server must listen on well-known STUN/TURN ports (typically 3478 UDP/TCP
  and 5349 for TLS) on the configured host addresses. Operators set `:listen` in
  application env or rely on defaults; this module centralises port resolution
  from env vars and rewrites listen specs at boot so config stays consistent.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (default TURN port 3478)
  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN on same port)
  """

  @default_turn_port 3478
  @default_turns_port 5349

  @doc """
  STUN/TURN plain (non-TLS) listen port.

  Reads `XTURN_STUN_PORT`, then `:stun_port` application env, then defaults to 3478.
  """
  @spec turn_port() :: pos_integer()
  def turn_port() do
    env_port("XTURN_STUN_PORT") || Application.get_env(:xturn, :stun_port) || @default_turn_port
  end

  @doc """
  TURNS (TLS) listen port.

  Reads `XTURN_TURNS_PORT` or defaults to 5349.
  """
  @spec turns_port() :: pos_integer()
  def turns_port() do
    env_port("XTURN_TURNS_PORT") || @default_turns_port
  end

  @doc "Returns UDP and TCP plain listener tuples on `ip` at `turn_port/0`."
  @spec plain_entries(charlist()) :: [{atom(), charlist(), pos_integer()}]
  def plain_entries(ip) do
    p = turn_port()
    [{:udp, ip, p}, {:tcp, ip, p}]
  end

  @doc "Returns UDP and TCP TLS listener tuples on `ip`, or `[]` when `certs?` is false."
  @spec secure_entries(charlist(), boolean()) :: [{atom(), charlist(), pos_integer(), :secure}]
  def secure_entries(_ip, false), do: []

  def secure_entries(ip, true) do
    p = turns_port()
    [{:udp, ip, p, :secure}, {:tcp, ip, p, :secure}]
  end

  @doc "Returns true when `:certs` config points at an existing certificate file."
  @spec certs_available?() :: boolean()
  def certs_available?() do
    case Application.get_env(:xturn, :certs, []) do
      certs when is_list(certs) ->
        certfile = Keyword.get(certs, :certfile) || certs["certfile"]
        is_binary(certfile) and File.exists?(certfile)

      _ ->
        false
    end
  end

  @doc """
  Default listen list: `0.0.0.0` and `::` for plain and (when certs exist) TLS.

  Pass `certs?` false to omit secure entries even if files are present.
  """
  @spec default_listen(boolean()) :: [tuple()]
  def default_listen(certs? \\ true) do
    plain_entries(~c"0.0.0.0") ++
      plain_entries(~c"::") ++
      secure_entries(~c"0.0.0.0", certs?) ++
      secure_entries(~c"::", certs?)
  end

  @doc "Appends plain and secure IPv6 listen entries for `ip6` to an existing list."
  @spec append_ipv6(list(), charlist(), boolean()) :: list()
  def append_ipv6(listen, ip6, certs?) do
    listen ++ plain_entries(ip6) ++ secure_entries(ip6, certs?)
  end

  @doc "Rewrites all listen tuple ports using current `turn_port/0` and `turns_port/0`."
  @spec rewrite_ports(list()) :: list()
  def rewrite_ports(listen) when is_list(listen) do
    rewrite_ports(listen, turn_port(), turns_port())
  end

  @doc "Rewrites listen tuple ports to explicit plain and TLS port numbers."
  @spec rewrite_ports(list(), pos_integer(), pos_integer()) :: list()
  def rewrite_ports(listen, turn_port, turns_port) when is_list(listen) do
    Enum.map(listen, fn
      {proto, ip, _port, :secure} -> {proto, ip, turns_port, :secure}
      {proto, ip, _port} -> {proto, ip, turn_port}
      other -> other
    end)
  end

  defp env_port(var) do
    case System.get_env(var) do
      nil -> nil
      value -> String.to_integer(value)
    end
  end
end
