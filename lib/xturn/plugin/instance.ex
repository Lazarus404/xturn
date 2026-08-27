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

defmodule Xirsys.XTurn.Plugin.Instance do
  @moduledoc """
  GenServer wrapper for a passive (out-of-band) relay plugin.

  ## What problem this solves

  Passive plugins must not run on the relay thread. This GenServer receives
  `{:frame, payload, frame}` messages from `Plugin.Dispatch`, forwards them to
  the plugin module's `handle_frame/3`, and decrements the shared inflight
  counter when processing completes. `close/2` invokes `handle_close/2` with
  the allocation's teardown reason so plugins learn why the relay ended, not
  only the supervisor's `:shutdown`.

  Internal: one instance per passive plugin per allocation. Plugin authors
  implement the behaviour module; this wrapper is framework plumbing.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN relay frames)
  """
  use GenServer
  require Logger

  alias Xirsys.XTurn.Plugin.Allocation

  @close_timeout 5_000

  @doc "Starts a passive plugin instance under the dynamic supervisor."
  def start_link({mod, %Allocation{} = allocation, plugin_opts, atomics_ref}) do
    GenServer.start_link(__MODULE__, {mod, allocation, plugin_opts, atomics_ref})
  end

  @doc """
  Runs `handle_close/2` with the allocation's own teardown reason and stops the
  instance. Without this the only reason a plugin could ever observe is the
  `:shutdown` the supervisor sends, which says nothing about why the allocation
  actually ended.
  """
  def close(pid, reason) do
    GenServer.call(pid, {:close, reason}, @close_timeout)
  catch
    :exit, _ -> :ok
  end

  @doc false
  @impl true
  def init({mod, allocation, plugin_opts, atomics_ref}) do
    Process.flag(:trap_exit, true)

    case mod.init(allocation, plugin_opts) do
      :ignore ->
        :ignore

      {:ok, state} ->
        {:ok, %{mod: mod, state: state, atomics: atomics_ref, closed: false}}
    end
  end

  @impl true
  @doc false
  def handle_call({:close, reason}, _from, state) do
    run_close(reason, state)
    {:stop, :normal, :ok, %{state | closed: true}}
  end

  @impl true
  @doc false
  def handle_info({:frame, payload, frame}, state) do
    new_state =
      case state.mod.handle_frame(payload, frame, state.state) do
        {:ok, plugin_state} -> plugin_state
        other ->
          Logger.warning("passive plugin #{inspect(state.mod)} returned #{inspect(other)}")
          state.state
      end

    :atomics.sub(state.atomics, 1, 1)
    {:noreply, %{state | state: new_state}}
  end

  @impl true
  @doc false
  def handle_info(msg, state) do
    if function_exported?(state.mod, :handle_info, 2) do
      case state.mod.handle_info(msg, state.state) do
        {:ok, new_state} ->
          {:noreply, %{state | state: new_state}}

        other ->
          Logger.warning(
            "passive plugin #{inspect(state.mod)} returned #{inspect(other)} for message #{inspect(msg)}"
          )

          {:noreply, state}
      end
    else
      Logger.debug("passive plugin #{inspect(state.mod)} ignoring message #{inspect(msg)}")
      {:noreply, state}
    end
  end

  @impl true
  @doc false
  def terminate(reason, state) do
    run_close(reason, state)
  end

  defp run_close(_reason, %{closed: true}), do: :ok

  defp run_close(reason, state) do
    if function_exported?(state.mod, :handle_close, 2) do
      state.mod.handle_close(reason, state.state)
    end

    :ok
  end
end
