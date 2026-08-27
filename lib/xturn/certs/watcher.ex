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

defmodule Xirsys.XTurn.Certs.Watcher do
  @moduledoc """
  Polls configured certificate files and reloads secure listeners on change.

  ## What problem this solves

  Automated renewals (lego hooks, certbot, manual copy) update PEM files on
  disk without restarting the BEAM. Polling detects content changes and calls
  `Certs.reload/0`. A two-poll debounce avoids reloading mid-copy when a hook
  writes cert and key sequentially. The initial poll records a baseline so
  boot does not bounce listeners.

  Internal: interval from `:cert_watch_interval_ms` (default 60 seconds).

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN over TLS listeners
    reloaded)
  """
  use GenServer

  require Logger

  alias Xirsys.XTurn.Certs

  @default_interval_ms 60_000

  @doc "Starts the certificate file watcher GenServer."
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)

    case name do
      nil -> GenServer.start_link(__MODULE__, opts)
      atom -> GenServer.start_link(__MODULE__, opts, name: atom)
    end
  end

  @doc false
  @impl true
  def init(opts) do
    interval_ms = fetch_lazy(opts, :interval_ms, &interval_ms/0)
    reload_fun = fetch_lazy(opts, :reload_fun, fn -> &Certs.reload/0 end)
    paths = fetch_lazy(opts, :paths, &Certs.paths/0)

    state = %{
      interval_ms: interval_ms,
      reload_fun: reload_fun,
      paths: paths,
      stable_hash: nil,
      debounce_hash: nil,
      bootstrapped?: false
    }

    schedule_poll(interval_ms)
    {:ok, state}
  end

  @impl true
  @doc false
  def handle_info(:poll, state) do
    state =
      case content_hash(state.paths) do
        nil -> state
        hash -> handle_poll(state, hash)
      end

    schedule_poll(state.interval_ms)
    {:noreply, state}
  end

  defp handle_poll(%{bootstrapped?: false} = state, hash) do
    %{state | stable_hash: hash, debounce_hash: nil, bootstrapped?: true}
  end

  defp handle_poll(%{stable_hash: stable} = state, hash) when stable == hash do
    %{state | debounce_hash: nil}
  end

  defp handle_poll(%{debounce_hash: debounce} = state, hash) when debounce == hash do
    Logger.info("XTurn: certificate files changed - reloading secure listeners")
    state.reload_fun.()

    %{state | stable_hash: hash, debounce_hash: nil}
  end

  defp handle_poll(state, hash) do
    %{state | debounce_hash: hash}
  end

  defp schedule_poll(interval_ms) do
    Process.send_after(self(), :poll, interval_ms)
  end

  defp fetch_lazy(opts, key, default_fun) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> value
      :error -> default_fun.()
    end
  end

  defp interval_ms do
    Application.get_env(:xturn, :cert_watch_interval_ms, @default_interval_ms)
  end

  defp content_hash(paths) do
    digests =
      Enum.map(paths, fn path ->
        case file_digest(path) do
          nil -> :missing
          digest -> digest
        end
      end)

    if Enum.any?(digests, &(&1 == :missing)) do
      nil
    else
      :crypto.hash(:sha256, Enum.join(digests, "|"))
    end
  end

  defp file_digest(path) do
    case File.read(path) do
      {:ok, data} ->
        :crypto.hash(:sha256, data)

      {:error, reason} ->
        Logger.debug("cert watcher: could not read #{inspect(path)}: #{inspect(reason)}")
        nil
    end
  end
end
