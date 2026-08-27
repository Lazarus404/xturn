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

defmodule Xirsys.XTurn.Plugin.Manager do
  @moduledoc """
  Loads relay plugins and monitors allocation lifetimes.

  ## What problem this solves

  XTurn extensions implement the plugin behaviour to observe or transform relay
  traffic (logging, recording, policy). This GenServer reads `:plugins` from
  application env, validates callback exports, caches the enabled list in
  `:persistent_term`, and registers `Process.monitor/1` refs for allocation
  owners and passive plugin instances.

  When an allocation owner exits, teardown runs in a spawned process so slow
  `handle_close/2` callbacks cannot block monitor handling. Call `reload/0`
  after changing plugin config at runtime.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN relay path plugins
    attach to)
  """
  use GenServer
  require Logger

  alias Xirsys.XTurn.Plugin.{Chain, Table}

  @framework_opts [:enabled, :fail, :max_inflight, :budget_us, :sample_every]

  @doc "Starts the plugin manager (registered as `__MODULE__`)."
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns the enabled plugin list loaded from application env."
  def plugins do
    :persistent_term.get({Xirsys.XTurn.Plugin, :plugins}, [])
  end

  @doc "Reloads the plugin list from application env and updates `:persistent_term`."
  def reload do
    GenServer.call(__MODULE__, :reload)
  end

  @doc """
  Registers monitors for one allocation: its owning `Allocate.Client` and each of
  its passive instances.

  Synchronous on purpose. A cast could land after the monitored process had already
  died, and `Process.monitor/1` on a dead pid reports `:noproc` rather than the real
  exit reason -- which is exactly the reason plugins are told about in
  `handle_close/2`. One call per allocation, never per frame.
  """
  def watch(tuple5, owner_pid, instances) do
    GenServer.call(__MODULE__, {:watch, tuple5, owner_pid, instances})
  end

  @doc "Returns plugin-specific options, stripping framework keys."
  def plugin_opts(opts), do: Keyword.drop(opts, @framework_opts)

  @doc "Reads a framework option from plugin config with a default."
  def framework_opt(opts, key, default) do
    Keyword.get(opts, key, default)
  end

  @doc false
  @impl true
  def init(_opts) do
    plugins = load_plugins()
    {:ok, %{plugins: plugins, monitors: %{}}}
  end

  @doc false
  @impl true
  def handle_call(:reload, _from, state) do
    plugins = load_plugins()
    {:reply, :ok, %{state | plugins: plugins}}
  end

  @impl true
  @doc false
  def handle_call({:watch, tuple5, owner_pid, instances}, _from, state) do
    monitors =
      Enum.reduce(instances, state.monitors, fn {pid, mod}, acc ->
        Map.put(acc, Process.monitor(pid), {:instance, pid, tuple5, mod})
      end)

    monitors =
      if is_pid(owner_pid) do
        Map.put(monitors, Process.monitor(owner_pid), {:allocation, owner_pid, tuple5, nil})
      else
        monitors
      end

    {:reply, :ok, %{state | monitors: monitors}}
  end

  @impl true
  @doc false
  def handle_info({:DOWN, ref, :process, pid, reason}, state) do
    {entry, monitors} = Map.pop(state.monitors, ref)
    handle_down(entry, pid, reason)
    {:noreply, %{state | monitors: monitors}}
  end

  defp handle_down(nil, _pid, _reason), do: :ok

  defp handle_down({:instance, pid, tuple5, mod}, pid, reason),
    do: prune_instance(tuple5, pid, mod, reason)

  # Teardown can call handle_close/2 on a plugin, which may flush to disk, so it
  # runs off this process -- Manager holds every allocation's monitor and must not
  # be blocked behind one slow plugin.
  defp handle_down({:allocation, pid, tuple5, _mod}, pid, reason) do
    spawn(fn -> Xirsys.XTurn.Plugin.Lifecycle.allocation_ended(tuple5, reason) end)
    :ok
  end

  defp handle_down(_entry, _pid, _reason), do: :ok

  defp load_plugins do
    plugins =
      Application.get_env(:xturn, :plugins, [])
      |> Enum.filter(fn {_mod, opts} -> Keyword.get(opts, :enabled, true) end)
      |> Enum.map(fn {mod, _opts} = entry ->
        validate_module!(mod)
        entry
      end)

    :persistent_term.put({Xirsys.XTurn.Plugin, :enabled}, plugins != [])
    :persistent_term.put({Xirsys.XTurn.Plugin, :plugins}, plugins)
    plugins
  end

  defp prune_instance(tuple5, pid, mod, reason) do
    case Table.get(tuple5) do
      nil ->
        :ok

      %Chain{} = chain ->
        pruned = %Chain{
          chain
          | egress_passive: reject_pid(chain.egress_passive, pid),
            ingress_passive: reject_pid(chain.ingress_passive, pid)
        }

        Table.put(tuple5, pruned)

        Logger.warning(
          "passive plugin #{inspect(mod)} died (#{inspect(reason)}), pruned pid #{inspect(pid)} from chain"
        )
    end
  end

  defp reject_pid(entries, pid) do
    Enum.reject(entries, fn {_mod, entry_pid, _ref, _max} -> entry_pid == pid end)
  end

  defp validate_module!(mod) do
    unless Code.ensure_loaded?(mod) do
      raise ArgumentError, "plugin module #{inspect(mod)} could not be loaded"
    end

    for {callback, arity} <- [
          {:mode, 0},
          {:hooks, 0},
          {:attach?, 2},
          {:init, 2},
          {:handle_frame, 3}
        ] do
      unless function_exported?(mod, callback, arity) do
        raise ArgumentError,
              "plugin #{inspect(mod)} must export #{callback}/#{arity}"
      end
    end

    case mod.mode() do
      mode when mode in [:active, :passive] -> :ok
      other -> raise ArgumentError, "plugin #{inspect(mod)} returned invalid mode #{inspect(other)}"
    end

    hooks = mod.hooks()

    unless is_list(hooks) and Enum.all?(hooks, &(&1 in [:egress, :ingress])) do
      raise ArgumentError, "plugin #{inspect(mod)} returned invalid hooks #{inspect(hooks)}"
    end
  end
end
