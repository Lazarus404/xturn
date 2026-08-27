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

defmodule Xirsys.XTurn.Plugin.InstanceSupervisor do
  @moduledoc """
  DynamicSupervisor for passive plugin GenServer instances.

  ## What problem this solves

  Passive plugins process relay frames out-of-band (disk I/O, external APIs)
  without blocking the relay hot path. Each allocation that attaches a passive
  plugin gets a temporary child under this supervisor; children restart is
  disabled (`:temporary`) because lifecycle is allocation-scoped.

  Internal: started by `Plugin.Lifecycle` via `start_instance/3`. Returns the
  child pid, shared inflight atomics ref, and `max_inflight` limit for
  `Plugin.Dispatch` back-pressure.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN relay frames
    delivered to passive plugins)
  """
  use DynamicSupervisor

  alias Xirsys.XTurn.Plugin.{Allocation, Instance, Manager}

  @doc "Starts the instance supervisor (registered as `__MODULE__`)."
  def start_link(opts \\ []) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  @impl true
  def init(_opts) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc """
  Starts a passive plugin instance for `allocation`.

  Returns `{:ok, pid, atomics_ref, max_inflight}`, `:ignore`, or `{:error, reason}`.
  """
  def start_instance(mod, %Allocation{} = allocation, opts) do
    max_inflight = Manager.framework_opt(opts, :max_inflight, 500)
    plugin_opts = Manager.plugin_opts(opts)
    atomics_ref = :atomics.new(1, signed: false)

    child_spec = %{
      id: {mod, allocation.id},
      start: {Instance, :start_link, [{mod, allocation, plugin_opts, atomics_ref}]},
      restart: :temporary,
      shutdown: 5_000
    }

    case DynamicSupervisor.start_child(__MODULE__, child_spec) do
      {:ok, pid} -> {:ok, pid, atomics_ref, max_inflight}
      :ignore -> :ignore
      other -> other
    end
  end
end
