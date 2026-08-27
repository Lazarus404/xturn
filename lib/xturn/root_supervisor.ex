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

defmodule Xirsys.XTurn.RootSupervisor do
  @moduledoc """
  Root OTP supervisor for TURN listeners and the HTTP API.

  ## What problem this solves

  XTurn exposes a REST API (Maru/Cowboy) alongside the relay. Crashing the API
  must not tear down active allocations and listeners. This supervisor starts
  the TURN tree and API as sibling children under `:one_for_one` so they fail
  independently.

  ## Internal note

  Started from `Xirsys.XTurn.start/2`; operators use HTTP config separately.

  ## RFCs

  - [RFC 7635](https://www.rfc-editor.org/rfc/rfc7635) (TURN REST API served by the API child)
  """
  use Supervisor

  @doc "Starts the root supervisor with the given listen tuple list."
  def start_link(listen) do
    Supervisor.start_link(__MODULE__, listen, name: __MODULE__)
  end

  @doc false
  @impl true
  def init(listen) do
    children = [
      Supervisor.child_spec({Xirsys.XTurn.Supervisor, listen}, id: :turn),
      %{id: :api, start: {Maru.Supervisor, :start_link, []}}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
