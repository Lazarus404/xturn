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

defmodule Xirsys.XTurn.RelayIngress do
  @moduledoc """
  Sharded supervisor for peer -> client relay ingress.

  ## What problem this solves

  When a peer sends UDP to the relay address, the server must deliver that
  payload back to the TURN client (as ChannelData or a Data indication).
  Relay sockets are sharded across workers by port so each GenServer drains
  its own `{active, N}` batch without mailbox contention.

  `assign_socket/2` moves relay socket ownership to the correct worker via
  `controlling_process/2`; workers permission-check, optionally run plugins,
  and send to the client through `DataPlane.to_client/4`.

  ## Internal

  Started under the application supervision tree; not called by integrators
  except indirectly during allocation setup.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - relayed transport address and peer -> client delivery (pt.2, pt.10, pt.11)
  """

  alias Xirsys.XTurn.RelayIngress.Worker

  @doc false
  def child_spec(_arg) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, []},
      type: :supervisor
    }
  end

  @doc "Starts the shard supervisor (`one_for_one`)."
  def start_link do
    children =
      for index <- 0..(shard_count() - 1) do
        Supervisor.child_spec({Worker, index}, id: {Worker, index})
      end

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__)
  end

  @doc "Returns the PID of the worker shard that owns relay traffic on `port`."
  def worker_for_port(port) when is_integer(port) do
    rem(port, shard_count())
    |> via()
    |> Process.whereis()
  end

  @doc "Registered name for shard `index` (`xturn_relay_ingress_N`)."
  def via(index), do: Worker.via(index)

  @doc """
  Assigns `socket` to the worker shard for `port`.

  Returns `:ok` on success or `{:error, :no_worker}` when the shard is not running.
  """
  def assign_socket(socket, port) when is_port(socket) do
    case worker_for_port(port) do
      pid when is_pid(pid) ->
        XSockets.Transport.UDP.controlling_process(socket, pid)

      _ ->
        {:error, :no_worker}
    end
  end

  @doc """
  Number of relay ingress worker shards.

  Configured via `:udp_listen_shards` (defaults to `System.schedulers_online/0`).
  """
  def shard_count do
    Application.get_env(:xturn, :udp_listen_shards, System.schedulers_online())
    |> max(1)
  end
end
