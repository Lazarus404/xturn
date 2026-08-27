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

defmodule Xirsys.XTurn.ListenRegistry do
  @moduledoc """
  Stable `{transport, socket}` lookup per bound `{ip, port}` endpoint.

  ## What problem this solves

  With SO_REUSEPORT, multiple UDP listener processes bind the same port. RFC 5780
  CHANGE-REQUEST replies must come from a predictable socket on the alternate
  address or port. The first shard to bind registers in this ETS table; later
  shards forward traffic but are not chosen as 5780 reply sources.

  ## Internal note

  Populated at listener startup by `DatagramListener`; not configured directly.

  ## RFCs

  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (alternate source for Binding replies)
  """

  @table :xturn_listen_registry

  @doc "Creates the public ETS table if it does not exist."
  @spec ensure!() :: :ok
  def ensure!() do
    case :ets.info(@table) do
      :undefined -> :ets.new(@table, [:named_table, :public, read_concurrency: true])
      _ -> @table
    end

    :ok
  end

  @doc """
  Records the first `{transport, socket}` bound to `endpoint`.

  Uses `:ets.insert_new/2` so only the first registrant wins (RFC 5780 stable source).
  """
  @spec register({:inet.ip_address(), :inet.port_number()}, {module(), term()}) :: :ok
  def register(endpoint, {transport, socket}) do
    ensure!()
    _ = :ets.insert_new(@table, {endpoint, {transport, socket}})
    :ok
  end

  @doc "Removes the registry entry for `endpoint`."
  @spec unregister({:inet.ip_address(), :inet.port_number()}) :: :ok
  def unregister(endpoint) do
    ensure!()
    :ets.delete(@table, endpoint)
    :ok
  end

  @doc "Looks up `{transport, socket}` for `endpoint`, or `:error` if unset."
  @spec lookup({:inet.ip_address(), :inet.port_number()}) ::
          {:ok, {module(), term()}} | :error
  def lookup(endpoint) do
    ensure!()

    case :ets.lookup(@table, endpoint) do
      [{^endpoint, entry}] -> {:ok, entry}
      [] -> :error
    end
  end
end
