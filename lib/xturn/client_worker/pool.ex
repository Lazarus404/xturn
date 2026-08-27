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

defmodule Xirsys.XTurn.ClientWorker.Pool do
  @moduledoc """
  Supervisor and dispatcher for sharded STUN/TURN control workers.

  ## What problem this solves

  STUN/TURN control handling mutates per-request `%Conn{}` state and must stay
  ordered per client endpoint. Hashing `{client_ip, client_port}` to a fixed
  worker serializes that client's requests without a global lock while still
  using multiple cores across clients.

  ## Internal note

  `dispatch/2` is called from socket handlers when a frame is classified as
  control-plane traffic.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN control transactions)
  """
  use Supervisor

  alias Xirsys.XTurn.ClientWorker

  @workers_key {__MODULE__, :workers}
  @size_key {__MODULE__, :size}

  @doc "Starts the worker pool supervisor (registered as `__MODULE__`)."
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Casts `frame` to the worker shard for `meta.client_ip` / `meta.client_port`.

  `meta` must include `:transport`, `:socket`, and server/client endpoints.
  """
  @spec dispatch(binary(), map()) :: :ok
  def dispatch(frame, meta) when is_binary(frame) and is_map(meta) do
    idx = :erlang.phash2({meta.client_ip, meta.client_port}, pool_size())
    GenServer.cast(worker_name(idx), {:process, frame, meta})
  end

  @doc "Configured pool size (`:client_worker_pool_size` or scheduler count)."
  @spec pool_size() :: pos_integer()
  def pool_size do
    case :persistent_term.get(@size_key, nil) do
      nil -> default_pool_size()
      size -> size
    end
  end

  @doc "Registered module atom for worker `index` (`ClientWorker.N`)."
  @spec worker_name(non_neg_integer()) :: atom()
  def worker_name(index) when is_integer(index) and index >= 0 do
    Module.concat([ClientWorker, Integer.to_string(index)])
  end

  @doc "Shard index for a client five-tuple (same hash as `dispatch/2`)."
  @spec worker_index(:inet.ip_address(), :inet.port_number()) :: non_neg_integer()
  def worker_index(client_ip, client_port) do
    :erlang.phash2({client_ip, client_port}, pool_size())
  end

  @doc false
  @impl true
  def init(_opts) do
    size = default_pool_size()
    workers = for index <- 0..(size - 1), do: worker_name(index)

    :persistent_term.put(@size_key, size)
    :persistent_term.put(@workers_key, workers)

    children =
      for index <- 0..(size - 1) do
        Supervisor.child_spec(
          {ClientWorker, [name: worker_name(index)]},
          id: {ClientWorker, index}
        )
      end

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp default_pool_size do
    Application.get_env(:xturn, :client_worker_pool_size, System.schedulers_online())
    |> max(1)
  end
end
