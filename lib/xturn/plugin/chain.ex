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

defmodule Xirsys.XTurn.Plugin.Chain do
  @moduledoc """
  Resolved plugin chain for one TURN allocation.

  ## What problem this solves

  After `Plugin.Lifecycle` evaluates which plugins attach to an allocation,
  the result must be a fixed ordered list for ingress and egress, split into
  active (inline) and passive (GenServer) entries. This struct is stored in
  `Plugin.Table` and consumed by `Plugin.Dispatch`.

  Internal: built at allocation start; claimed via `Plugin.Table.take/1` at
  teardown.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN relay allocations)
  """

  @typedoc "Active plugin entry: `{module, opaque_state, opts}` run inline on the hot path."
  @type active_entry :: {module(), term(), keyword()}

  @typedoc "Passive plugin entry: `{module, pid, atomics_ref, generation}` notified after active work."
  @type passive_entry :: {module(), pid(), :atomics.atomics_ref(), non_neg_integer()}

  @typedoc """
  Ordered plugin entries for one allocation's ingress and egress paths.

  ## Fields

  - `:egress_active` - active plugins run before relaying toward the peer
  - `:egress_passive` - passive plugins notified after active egress succeeds
  - `:ingress_active` - active plugins run before delivering toward the client
  - `:ingress_passive` - passive plugins notified after active ingress succeeds
  """
  @type t :: %__MODULE__{
          egress_active: [active_entry()],
          egress_passive: [passive_entry()],
          ingress_active: [active_entry()],
          ingress_passive: [passive_entry()]
        }

  defstruct egress_active: [],
            egress_passive: [],
            ingress_active: [],
            ingress_passive: []

  @doc "Returns an empty plugin chain with no active or passive entries."
  def empty, do: %__MODULE__{}
end
