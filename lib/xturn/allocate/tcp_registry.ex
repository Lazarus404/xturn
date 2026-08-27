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

defmodule Xirsys.XTurn.Allocate.TcpRegistry do
  @moduledoc """
  ETS registries for RFC 6062 TCP relay connection ids and spliced sockets.

  ## What problem this solves

  TCP relay uses CONNECTION-ID to tie Connect, ConnectionBind, and ConnectionAttempt
  to the owning allocation. After ConnectionBind splices client and peer TCP
  sockets, the STUN framer must stop processing those ports as TURN control.

  ## Internal note

  Updated by `Allocate.Client` during Connect/Bind/splice.

  ## RFCs

  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TCP relay, CONNECTION-ID)
  """

  @conn_ids :xturn_connection_ids
  @spliced :xturn_spliced_sockets

  @doc "Registers `connection_id` to the owning allocation `alloc_pid`. Returns `:ok`."
  def register(connection_id, alloc_pid) when is_binary(connection_id) and is_pid(alloc_pid) do
    ensure(@conn_ids)
    :ets.insert(@conn_ids, {connection_id, alloc_pid})
    :ok
  end

  @doc "Removes a CONNECTION-ID registration. Returns `:ok`."
  def unregister(connection_id) when is_binary(connection_id) do
    ensure(@conn_ids)
    :ets.delete(@conn_ids, connection_id)
    :ok
  end

  @doc """
  Resolves a CONNECTION-ID to its allocation pid.

  Returns `{:ok, pid}` or `:error`.
  """
  def lookup_alloc(connection_id) when is_binary(connection_id) do
    ensure(@conn_ids)

    case :ets.lookup(@conn_ids, connection_id) do
      [{^connection_id, pid}] when is_pid(pid) -> {:ok, pid}
      _ -> :error
    end
  end

  @doc "Records that `socket` has been spliced to a peer TCP connection. Returns `:ok`."
  def mark_spliced(socket) when is_port(socket) do
    ensure(@spliced)
    :ets.insert(@spliced, {socket, true})
    :ok
  end

  @doc "Returns whether `socket` has been marked spliced."
  def spliced?(socket) when is_port(socket) do
    case :ets.whereis(@spliced) do
      :undefined -> false
      _ -> :ets.member(@spliced, socket)
    end
  end

  @doc false
  def spliced?(_), do: false

  defp ensure(table) do
    case :ets.whereis(table) do
      :undefined -> :ets.new(table, [:named_table, :public, :set, {:write_concurrency, true}])
      _ -> :ok
    end
  end
end
