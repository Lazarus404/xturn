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

defmodule Xirsys.XTurn.Allocate.Bytes do
  @moduledoc """
  Lock-free per-allocation relay byte counters.

  ## What problem this solves

  The media fast path increments byte counts from many processes without blocking
  the allocation GenServer. Each allocation registers an `:atomics` ref in ETS;
  `add_in/2` and `add_out/2` update counters on the hot path; `merge/2` drains
  them into `%Client.State{}` periodically.

  ## Internal note

  Billing and quota integrations read merged totals from allocation state.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (relayed traffic accounting)
  """

  @bytes_in 1
  @bytes_out 2

  @doc "Creates the public byte-counter ETS table if it does not exist."
  def init do
    if :ets.whereis(__MODULE__) == :undefined do
      :ets.new(__MODULE__, [:named_table, :public, :set, read_concurrency: true])
    end

    :ok
  end

  @doc """
  Registers `pid` and returns a fresh atomic counter ref.

  The ref is also stored in ETS for cross-process increments.
  """
  def register(pid) do
    ref = :atomics.new(2, signed: false)
    :ets.insert(__MODULE__, {pid, ref})
    ref
  end

  @doc "Removes the byte counter entry for `pid`."
  def unregister(pid), do: :ets.delete(__MODULE__, pid)

  @doc "Adds `nbytes` to the outbound relay counter for `pid`."
  def add_out(pid, nbytes) when is_integer(nbytes) and nbytes > 0 do
    case :ets.lookup(__MODULE__, pid) do
      [{^pid, ref}] -> :atomics.add(ref, @bytes_out, nbytes)
      _ -> :ok
    end
  end

  @doc "Adds `nbytes` to the inbound relay counter for `pid`."
  def add_in(pid, nbytes) when is_integer(nbytes) and nbytes > 0 do
    case :ets.lookup(__MODULE__, pid) do
      [{^pid, ref}] -> :atomics.add(ref, @bytes_in, nbytes)
      _ -> :ok
    end
  end

  @doc """
  Drains pending atomic counters for `pid` into `state.bytes_in` and `state.bytes_out`.

  Returns updated `state`; unchanged when `pid` is not registered.
  """
  def merge(state, pid) do
    case :ets.lookup(__MODULE__, pid) do
      [{^pid, ref}] ->
        bytes_in = :atomics.get(ref, @bytes_in)
        bytes_out = :atomics.get(ref, @bytes_out)

        if bytes_in != 0, do: :atomics.sub(ref, @bytes_in, bytes_in)
        if bytes_out != 0, do: :atomics.sub(ref, @bytes_out, bytes_out)

        %{state | bytes_in: state.bytes_in + bytes_in, bytes_out: state.bytes_out + bytes_out}

      _ ->
        state
    end
  end
end
