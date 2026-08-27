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

defmodule Xirsys.XTurn.Plugin.Lifecycle do
  @moduledoc """
  Attaches and detaches relay plugins when allocations start and end.

  ## What problem this solves

  Plugins must bind to a specific TURN allocation for their lifetime: active
  modules run inline on each frame; passive modules get a dedicated GenServer.
  This module builds the per-allocation `Plugin.Chain` from configured modules,
  writes it to `Plugin.Table`, registers monitors via `Plugin.Manager`, and
  tears down passive instances with the allocation's actual exit reason.

  Called from allocation setup and owner monitor paths. Errors are logged and
  never fail the underlying Allocate.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN allocations plugins
    follow)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (updated TURN allocation
    lifecycle)
  """
  require Logger

  alias Xirsys.XTurn.Plugin.{
    Allocation,
    Chain,
    Instance,
    InstanceSupervisor,
    Manager,
    Table
  }

  @doc """
  Attaches plugins for a new allocation and registers teardown monitors.

  Writes the plugin chain to `Plugin.Table` before registering monitors so a
  concurrent `:DOWN` cannot arrive before the row exists.
  """
  def allocation_started(%Allocation{} = allocation) do
    try do
      {chain, instances} = build_chain(Manager.plugins(), allocation)
      Table.put(allocation.tuple5, chain)

      # The row is written before any monitor is registered, so a :DOWN can never
      # arrive before there is a row to act on.
      #
      # The owner is monitored because Allocate.Client does not trap exits: its
      # terminate/2, and with it the allocation_ended hook, is skipped whenever the
      # supervisor shuts it down rather than it stopping itself.
      Manager.watch(allocation.tuple5, allocation.owner_pid, instances)
    rescue
      exception ->
        Logger.error(
          "plugin allocation_started failed for #{inspect(allocation.tuple5)}: #{Exception.format(:error, exception)}"
        )
    catch
      :exit, reason ->
        Logger.error(
          "plugin allocation_started exited for #{inspect(allocation.tuple5)}: #{inspect(reason)}"
        )
    end

    :ok
  end

  @doc """
  Detaches plugins and stops passive instances for a ended allocation.

  Atomically claims the chain row via `Table.take/1` so concurrent teardown
  paths cannot both act on the same instances.
  """
  def allocation_ended(tuple5, reason) do
    try do
      # take/1 claims the row atomically, so the allocation's own terminate/2 and
      # the owner monitor racing each other can never both tear down the same
      # instances.
      case Table.take(tuple5) do
        nil -> :ok
        chain -> stop_passive_instances(chain, tuple5, reason)
      end
    rescue
      exception ->
        Logger.error(
          "plugin allocation_ended failed for #{inspect(tuple5)}: #{Exception.format(:error, exception)}"
        )
    catch
      :exit, exit_reason ->
        Logger.error(
          "plugin allocation_ended exited for #{inspect(tuple5)}: #{inspect(exit_reason)}"
        )
    end

    :ok
  end

  defp build_chain(plugins, allocation) do
    Enum.reduce(plugins, {Chain.empty(), []}, fn {mod, opts}, {chain, instances} ->
      plugin_opts = Manager.plugin_opts(opts)

      if mod.attach?(allocation, plugin_opts) do
        add_plugin(chain, instances, mod, opts, plugin_opts, allocation)
      else
        {chain, instances}
      end
    end)
  end

  defp add_plugin(%Chain{} = chain, instances, mod, opts, plugin_opts, allocation) do
    hooks = mod.hooks()

    case mod.mode() do
      :active ->
        case mod.init(allocation, plugin_opts) do
          :ignore ->
            {chain, instances}

          {:ok, state} ->
            emit_attached(mod, allocation.tuple5)
            {add_active_entries(chain, mod, state, opts, hooks), instances}
        end

      :passive ->
        case InstanceSupervisor.start_instance(mod, allocation, opts) do
          {:ok, pid, atomics_ref, max_inflight} ->
            emit_attached(mod, allocation.tuple5)

            {
              add_passive_entries(chain, mod, pid, atomics_ref, max_inflight, hooks),
              [{pid, mod} | instances]
            }

          :ignore ->
            {chain, instances}

          {:error, reason} ->
            Logger.warning("failed to start passive plugin #{inspect(mod)}: #{inspect(reason)}")
            {chain, instances}
        end
    end
  end

  defp add_active_entries(%Chain{} = chain, mod, state, opts, hooks) do
    entry = {mod, state, opts}

    %Chain{
      chain
      | egress_active: maybe_prepend(hooks, :egress, entry, chain.egress_active),
        ingress_active: maybe_prepend(hooks, :ingress, entry, chain.ingress_active)
    }
  end

  defp add_passive_entries(%Chain{} = chain, mod, pid, atomics_ref, max_inflight, hooks) do
    entry = {mod, pid, atomics_ref, max_inflight}

    %Chain{
      chain
      | egress_passive: maybe_prepend(hooks, :egress, entry, chain.egress_passive),
        ingress_passive: maybe_prepend(hooks, :ingress, entry, chain.ingress_passive)
    }
  end

  defp maybe_prepend(hooks, direction, entry, existing) do
    if direction in hooks, do: existing ++ [entry], else: existing
  end

  defp stop_passive_instances(%Chain{} = chain, tuple5, reason) do
    chain.egress_passive
    |> Kernel.++(chain.ingress_passive)
    |> Enum.uniq_by(fn {_mod, pid, _atomics, _max} -> pid end)
    |> Enum.each(fn {mod, pid, _atomics, _max} -> stop_instance(mod, pid, tuple5, reason) end)

    :ok
  end

  defp stop_instance(mod, pid, tuple5, reason) do
    Instance.close(pid, reason)
    DynamicSupervisor.terminate_child(Xirsys.XTurn.Plugin.InstanceSupervisor, pid)

    :telemetry.execute(
      [:xturn, :plugin, :detached],
      %{},
      %{module: mod, tuple5: tuple5, reason: reason}
    )
  catch
    :exit, _ -> :ok
  end

  defp emit_attached(mod, tuple5) do
    :telemetry.execute([:xturn, :plugin, :attached], %{}, %{module: mod, tuple5: tuple5})
  end
end
