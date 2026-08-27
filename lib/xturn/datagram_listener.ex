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

defmodule Xirsys.XTurn.DatagramListener do
  @moduledoc """
  UDP listener that registers bound endpoints in `ListenRegistry`.

  ## What problem this solves

  SO_REUSEPORT spreads UDP receives across shards, but RFC 5780 needs a stable
  `{transport, socket}` for alternate-source Binding replies. This wrapper starts
  `DatagramServer` and registers `{ip, port}` on boot so `DualIp.reply_from/3`
  can resolve the correct shard.

  ## Internal note

  Used as the child module for UDP listeners in `Supervisor`; not configured directly.

  ## RFCs

  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (CHANGE-REQUEST reply socket)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN over UDP)
  """

  alias XSockets.DatagramServer
  alias Xirsys.XTurn.ListenRegistry

  @doc false
  def child_spec(opts) do
    %{
      id: {__MODULE__, opts},
      start: {__MODULE__, :start_link, [opts]},
      restart: :permanent,
      shutdown: 5000,
      type: :worker
    }
  end

  @doc """
  Starts `DatagramServer` and registers `{ip, port}` in `ListenRegistry`.

  Options are forwarded to `DatagramServer.start_link/1`; `:transport` is required.
  """
  def start_link(opts) do
    transport = Keyword.fetch!(opts, :transport)

    with {:ok, pid} <- DatagramServer.start_link(opts),
         :ok <- register(pid, transport) do
      {:ok, pid}
    end
  end

  defp register(pid, transport) do
    socket = DatagramServer.socket(pid)
    {ip, port} = DatagramServer.endpoint(pid)
    ListenRegistry.register({ip, port}, {transport, socket})
  end
end
