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

defmodule Xirsys.XTurn.Plugin.Table do
  @moduledoc """
  ETS-backed table mapping normalised allocation keys to plugin chains.

  ## What problem this solves

  Relay plugins attach per allocation and must be looked up on every ingress/
  egress frame without a GenServer hop. This table stores the resolved
  `Plugin.Chain` for each normalised five-tuple key so `Plugin.Dispatch` can
  read concurrently from the data plane.

  Internal: keys normalise protocol to `:_` so UDP and TCP variants of the same
  allocation match. Use `take/1` during teardown to claim a row atomically.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN relay allocations
    plugins observe)
  """
  alias Xirsys.XTurn.Tuple5, as: T5

  @doc "Creates the named public plugin chain table."
  def init do
    :ets.new(__MODULE__, [:set, :public, :named_table, read_concurrency: true])
    :ok
  end

  @doc """
  Normalises a tuple5 key so ingress and egress lookups agree.
  """
  def normalise(%T5{} = tuple5), do: normalise(T5.to_map(tuple5))

  def normalise([{:ca, ca}, {:cp, cp}, {:sa, sa}, {:sp, sp}, {:proto, _}]),
    do: [{:ca, ca}, {:cp, cp}, {:sa, sa}, {:sp, sp}, {:proto, :_}]

  @doc "Stores `chain` for the normalised `tuple5` key."
  def put(tuple5, chain) do
    :ets.insert(__MODULE__, {key(tuple5), chain})
    :ok
  end

  @doc "Returns the plugin chain for `tuple5`, or `nil` when none is attached."
  def get(tuple5) do
    case :ets.lookup(__MODULE__, key(tuple5)) do
      [{_key, chain}] -> chain
      [] -> nil
    end
  end

  @doc "Deletes the row for `tuple5` without returning it."
  def delete(tuple5) do
    :ets.delete(__MODULE__, key(tuple5))
    :ok
  end

  @doc """
  Reads and deletes the row in one operation, so two concurrent teardowns of the
  same allocation cannot both act on the chain.
  """
  def take(tuple5) do
    case :ets.take(__MODULE__, key(tuple5)) do
      [{_key, chain}] -> chain
      [] -> nil
    end
  end

  defp key(tuple5), do: normalise(tuple5)
end
