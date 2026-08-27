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

defmodule Xirsys.XTurn.Certs.SignalHandler do
  @moduledoc """
  `:gen_event` handler that reloads TLS certificates on SIGHUP.

  ## What problem this solves

  Deployment hooks (systemd, `xturn-deploy-certs.sh`) can signal the running
  node to pick up renewed PEM files immediately instead of waiting for the
  poll interval. This handler invokes `Certs.reload/0` when the BEAM receives
  `:sighup`.

  Internal: registered on `:erl_signal_server` by
  `Certs.SignalHandler.Registrar` at boot.

  ## RFCs

  No STUN/TURN RFC applies. Operations concern for TLS/DTLS certificates
  used with TURNS (see [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656)
  for TURN over TLS/DTLS transports).
  """
  @behaviour :gen_event

  alias Xirsys.XTurn.Certs

  @impl :gen_event
  @doc false
  def init(_args), do: {:ok, %{}}

  @impl :gen_event
  @doc false
  def handle_event(:sighup, state) do
    Certs.reload()
    {:ok, state}
  end

  @doc false
  def handle_event(_event, state), do: {:ok, state}

  @impl :gen_event
  @doc false
  def handle_call(_request, state), do: {:ok, :ok, state}

  @impl :gen_event
  @doc false
  def handle_info(_msg, state), do: {:ok, state}

  @impl :gen_event
  @doc false
  def terminate(_args, _state), do: :ok

  @impl :gen_event
  @doc false
  def code_change(_old, state, _extra), do: {:ok, state}
end

defmodule Xirsys.XTurn.Certs.SignalHandler.Registrar do
  @moduledoc """
  Installs the SIGHUP certificate reload handler at boot.

  ## What problem this solves

  The signal handler must be registered once during application start and kept
  alive for the node lifetime. This GenServer sets `:os.set_signal(:sighup,
  :handle)`, adds `SignalHandler` to `:erl_signal_server`, and stops if the
  handler is removed unexpectedly so ops can detect misconfiguration.

  Internal: started from the application supervision tree.

  ## RFCs

  No STUN/TURN RFC applies. Pairs with `Certs.SignalHandler` for TURNS
  certificate reload (TLS/DTLS transports in
  [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656)).
  """
  use GenServer

  require Logger

  alias Xirsys.XTurn.Certs.SignalHandler

  @doc "Starts the registrar (registered as `__MODULE__`)."
  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc false
  @impl true
  def init([]) do
    :ok = :os.set_signal(:sighup, :handle)
    :ok = :gen_event.add_sup_handler(:erl_signal_server, SignalHandler, [])
    {:ok, %{}}
  end

  @doc false
  @impl true
  def handle_info({:gen_event_EXIT, SignalHandler, reason}, state)
      when reason in [:normal, :shutdown] do
    {:stop, :normal, state}
  end

  def handle_info({:gen_event_EXIT, SignalHandler, reason}, state) do
    Logger.warning("SIGHUP handler removed: #{inspect(reason)}")
    {:stop, {:handler_removed, reason}, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}
end
