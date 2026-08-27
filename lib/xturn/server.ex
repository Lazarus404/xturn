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

defmodule Xirsys.XTurn.Server do
  @moduledoc """
  Placeholder GenServer for OTP supervision compatibility.

  ## What problem this solves

  Older deployments expected a registered `Xirsys.XTurn.Server` process in the
  supervision tree. The server keeps this empty GenServer so upgrades do not
  break release scripts; live listeners and request handling run under
  `RootSupervisor`, `Supervisor`, and `ClientWorker.Pool`.

  ## Internal note

  No operator-facing behavior; retained for tree shape only.

  ## RFCs

  - (none; structural OTP component)
  """
  use GenServer
  @vsn "0"

  #####
  # External API

  @doc "Starts the application GenServer registered as `Xirsys.XTurn.Server`."
  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  #########################################################################################################################
  # OTP functions
  #########################################################################################################################

  @doc false
  def init([]) do
    # {:ok, node_name} = :application.get_env(:node_name)
    # {:ok, node_host} = :application.get_env(:node_host)
    # {:ok, _} = Node.start(String.to_atom("#{node_name}@#{node_host}"))
    # {:ok, cookie} = :application.get_env(:cookie)
    # Node.set_cookie(cookie)
    {:ok, {}}
  end
end
