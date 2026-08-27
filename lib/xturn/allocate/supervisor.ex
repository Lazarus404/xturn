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

defmodule Xirsys.XTurn.Allocate.Supervisor do
  @moduledoc """
  Dynamic supervisor for per-client TURN allocation GenServers.

  ## What problem this solves

  Each successful Allocate spawns a dedicated process for relay state. A
  `:simple_one_for_one` supervisor with `:temporary` restarts lets allocations
  start and stop independently without restarting siblings when one client leaves.

  ## Internal note

  Child module is typically `Allocate.Client`.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (allocation lifetime and teardown)
  """
  use Supervisor

  @doc """
  Starts the allocation supervisor.

  ## Parameters

    * `alloc` - allocation worker module (typically `Allocate.Client`)
  """
  def start_link(alloc) do
    :supervisor.start_link({:local, __MODULE__}, __MODULE__, alloc)
  end

  @doc """
  Starts a new allocation worker under this supervisor.

  ## Parameters

    * `id` - allocation transaction id / store key
    * `listener` - client `%ClientSocket{}`
    * `tuple5` - client five-tuple
    * `lifetime` - initial lifetime in seconds
  """
  def start_child(id, listener, tuple5, lifetime) do
    :supervisor.start_child(__MODULE__, [id, listener, tuple5, lifetime])
  end

  @doc "Terminates an allocation worker pid."
  def terminate_child(child) do
    :supervisor.terminate_child(__MODULE__, child)
  end

  @doc false
  def init(alloc) do
    flags = %{strategy: :simple_one_for_one, intensity: 3, period: 5}
    children = [%{id: alloc, start: {alloc, :start_link, []}, restart: :temporary}]
    {:ok, {flags, children}}
  end
end
