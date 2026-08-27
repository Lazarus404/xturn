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

defmodule Xirsys.XTurn.PacketLog.Writer do
  @moduledoc """
  Serialises packet log lines to a dedicated file.

  ## What problem this solves

  `PacketLog` runs on the STUN/TURN hot path and must not block on disk I/O.
  This GenServer accepts append casts and writes lines to `:packet_log_path`
  (default `log/packets.log`). Write failures are swallowed so logging never
  crashes relay traffic.

  Internal: started from the application supervision tree.

  ## RFCs

  No STUN/TURN RFC applies. Operational tracing of datagrams that carry
  [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) /
  [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) traffic.
  """
  use GenServer

  @default_log_path "log/packets.log"

  @doc "Starts the writer (registered as `__MODULE__`)."
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Asynchronously appends one log line (without a trailing newline)."
  @spec append(String.t()) :: :ok
  def append(line) when is_binary(line) do
    GenServer.cast(__MODULE__, {:append, line})
  end

  @doc false
  @impl true
  def init(_opts) do
    path = Application.get_env(:xturn, :packet_log_path, @default_log_path)
    File.mkdir_p!(Path.dirname(path))

    case File.open(path, [:append, :utf8]) do
      {:ok, fd} ->
        {:ok, %{fd: fd, path: path}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  @doc false
  def handle_cast({:append, line}, state) do
    IO.write(state.fd, line <> "\n")
    {:noreply, state}
  rescue
    _ -> {:noreply, state}
  end

  @impl true
  @doc false
  def terminate(_reason, state) do
    File.close(state.fd)
    :ok
  end
end
