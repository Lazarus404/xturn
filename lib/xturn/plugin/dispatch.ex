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

defmodule Xirsys.XTurn.Plugin.Dispatch do
  @moduledoc """
  Runs the per-allocation plugin chain on relay ingress and egress.

  ## What problem this solves

  Relay traffic must optionally pass through configured plugins before reaching
  peers or clients. When plugins are disabled, payloads pass through unchanged.
  Active plugins transform or drop frames inline; passive plugins receive copies
  via message send with bounded inflight back-pressure and latency budgets.

  Internal: called from the data plane on every relay frame. Fail-open vs
  fail-closed behaviour is per-plugin via the `:fail` framework option.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN Send/Data and
    ChannelData relay path)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (updated TURN relay
    semantics)
  """
  require Logger

  alias Xirsys.XTurn.Plugin.{Chain, Frame, Manager, Table}

  @doc """
  Runs egress plugins for an allocation before relaying to a peer.

  Returns `{:ok, payload}` with the (possibly transformed) payload, or `:drop`
  when an active plugin or fail-closed policy rejects the frame.
  """
  @spec egress(term(), binary(), atom(), {term(), term()}, integer() | nil) ::
          {:ok, binary()} | :drop
  def egress(tuple5, payload, framing, peer_address, channel_number) do
    if enabled?() do
      do_egress(tuple5, payload, framing, peer_address, channel_number)
    else
      {:ok, payload}
    end
  end

  @doc """
  Runs ingress plugins for an allocation before delivering to the client.

  Returns `{:ok, payload}` with the (possibly transformed) payload, or `:drop`
  when an active plugin or fail-closed policy rejects the frame.
  """
  @spec ingress(term(), binary(), atom(), {term(), term()}) :: {:ok, binary()} | :drop
  def ingress(tuple5, payload, framing, peer_address) do
    if enabled?() do
      do_ingress(tuple5, payload, framing, peer_address)
    else
      {:ok, payload}
    end
  end

  defp enabled?, do: :persistent_term.get({Xirsys.XTurn.Plugin, :enabled}, false)

  defp do_egress(tuple5, payload, framing, {peer_ip, peer_port} = _peer_address, channel_number) do
    case Table.get(tuple5) do
      nil ->
        {:ok, payload}

      %Chain{} = chain ->
        frame = build_frame(:egress, framing, peer_ip, peer_port, channel_number, payload)

        case run_active(chain.egress_active, payload, frame, :egress) do
          {:ok, payload} = ok ->
            notify_passive(chain.egress_passive, payload, frame, :egress)
            ok

          :drop ->
            :drop
        end
    end
  end

  defp do_ingress(tuple5, payload, framing, {peer_ip, peer_port} = _peer_address) do
    case Table.get(tuple5) do
      nil ->
        {:ok, payload}

      %Chain{} = chain ->
        frame = build_frame(:ingress, framing, peer_ip, peer_port, nil, payload)

        case run_active(chain.ingress_active, payload, frame, :ingress) do
          {:ok, payload} = ok ->
            notify_passive(chain.ingress_passive, payload, frame, :ingress)
            ok

          :drop ->
            :drop
        end
    end
  end

  defp build_frame(direction, framing, peer_ip, peer_port, channel_number, payload) do
    %Frame{
      direction: direction,
      framing: framing,
      peer_ip: peer_ip,
      peer_port: peer_port,
      channel_number: channel_number,
      size: byte_size(payload),
      at: System.monotonic_time(:microsecond)
    }
  end

  defp run_active([], payload, _frame, _direction), do: {:ok, payload}

  defp run_active([{mod, state, opts} | rest], payload, frame, direction) do
    if plugin_disabled?(mod) do
      run_active(rest, payload, frame, direction)
    else
      fail = Manager.framework_opt(opts, :fail, :open)
      budget_us = Manager.framework_opt(opts, :budget_us, 500)
      sample_every = Manager.framework_opt(opts, :sample_every, 256)

      result =
        try do
          invoke_active(mod, state, payload, frame, direction, budget_us, sample_every)
        rescue
          exception ->
            :telemetry.execute(
              [:xturn, :plugin, :active, :exception],
              %{},
              %{module: mod, direction: direction, kind: :error, reason: exception}
            )

            if fail == :closed, do: :drop, else: {:ok, payload}
        catch
          kind, reason ->
            :telemetry.execute(
              [:xturn, :plugin, :active, :exception],
              %{},
              %{module: mod, direction: direction, kind: kind, reason: reason}
            )

            if fail == :closed, do: :drop, else: {:ok, payload}
        end

      case result do
        :drop ->
          emit_active_dropped(mod, direction, payload)
          :drop

        {:error, _reason} ->
          if fail == :closed do
            emit_active_dropped(mod, direction, payload)
            :drop
          else
            run_active(rest, payload, frame, direction)
          end

        {:ok, new_payload} ->
          run_active(rest, new_payload, frame, direction)
      end
    end
  end

  defp invoke_active(mod, state, payload, frame, direction, budget_us, sample_every) do
    counter = sample_counter(mod)
    count = :atomics.add_get(counter, 1, 1)

    if rem(count, sample_every) == 0 do
      start = System.monotonic_time(:microsecond)
      result = mod.handle_frame(payload, frame, state)
      elapsed = System.monotonic_time(:microsecond) - start
      record_sample(mod, direction, elapsed, budget_us, sample_every)
      result
    else
      mod.handle_frame(payload, frame, state)
    end
  end

  defp notify_passive([], _payload, _frame, _direction), do: :ok

  defp notify_passive([{mod, pid, atomics_ref, max_inflight} | rest], payload, frame, direction) do
    inflight = :atomics.add_get(atomics_ref, 1, 1)

    if inflight > max_inflight do
      :atomics.sub(atomics_ref, 1, 1)

      :telemetry.execute(
        [:xturn, :plugin, :passive, :dropped],
        %{bytes: byte_size(payload), inflight: inflight},
        %{module: mod, direction: direction}
      )
    else
      send(pid, {:frame, payload, frame})

      :telemetry.execute(
        [:xturn, :plugin, :passive, :dispatched],
        %{bytes: byte_size(payload)},
        %{module: mod, direction: direction}
      )
    end

    notify_passive(rest, payload, frame, direction)
  end

  defp emit_active_dropped(mod, direction, payload) do
    :telemetry.execute(
      [:xturn, :plugin, :active, :dropped],
      %{bytes: byte_size(payload)},
      %{module: mod, direction: direction}
    )
  end

  defp plugin_disabled?(mod),
    do: :persistent_term.get({Xirsys.XTurn.Plugin, :disabled, mod}, false)

  defp sample_counter(mod) do
    case :persistent_term.get({__MODULE__, :sample_counter, mod}, nil) do
      nil ->
        counter = :atomics.new(1, signed: false)
        :persistent_term.put({__MODULE__, :sample_counter, mod}, counter)
        counter

      counter ->
        counter
    end
  end

  defp record_sample(mod, direction, elapsed_us, budget_us, sample_every) do
    :telemetry.execute(
      [:xturn, :plugin, :active, :stop],
      %{duration: elapsed_us},
      %{module: mod, direction: direction}
    )

    mean_ref = mean_ref(mod)
    old_mean = :atomics.get(mean_ref, 1)

    new_mean =
      if old_mean == 0 do
        elapsed_us
      else
        div(old_mean * (sample_every - 1) + elapsed_us, sample_every)
      end

    :atomics.put(mean_ref, 1, new_mean)

    if new_mean > budget_us do
      :persistent_term.put({Xirsys.XTurn.Plugin, :disabled, mod}, true)

      Logger.error(
        "plugin #{inspect(mod)} disabled: mean latency #{new_mean}us exceeds budget #{budget_us}us"
      )

      :telemetry.execute(
        [:xturn, :plugin, :active, :disabled],
        %{mean_us: new_mean},
        %{module: mod}
      )
    end
  end

  defp mean_ref(mod) do
    case :persistent_term.get({__MODULE__, :mean_ref, mod}, nil) do
      nil ->
        ref = :atomics.new(1, signed: false)
        :persistent_term.put({__MODULE__, :mean_ref, mod}, ref)
        ref

      ref ->
        ref
    end
  end
end
