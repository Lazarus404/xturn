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

defmodule Xirsys.XTurn.Supervisor do
  @moduledoc """
  OTP supervisor for the TURN server worker tree.

  ## What problem this solves

  A running TURN node needs many cooperating processes: allocation workers,
  authentication, relay ingress, client worker pool, plugins, certificate
  watchers, and one or more UDP/TCP (or DTLS/TLS) listeners per configured
  address. This supervisor starts them in a fixed order from the `:listen` list.

  ## Internal note

  Started by `RootSupervisor`; operators configure `:listen` and related env,
  not this module directly.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN listeners and relay)
  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (first UDP shard registers in `ListenRegistry`)
  """
  use Supervisor

  @doc "Starts the TURN supervisor with the given listen tuple list."
  def start_link(listen) do
    Supervisor.start_link(__MODULE__, [listen], name: __MODULE__)
  end

  alias XSockets.{
    Acceptor,
    DatagramServer,
    SockSupervisor,
    TierSupervisor,
    Transport
  }

  alias Xirsys.XTurn.{Allocate, Auth, ClientWorker, DatagramListener, PacketLog, Plugin, Server,
                       SocketPipeline}
  alias Xirsys.XTurn.Certs.{SignalHandler, Watcher}

  @doc """
  Restarts secure TURN/TLS listeners so they pick up renewed certificate files.
  """
  @spec restart_secure_listeners() :: :ok
  def restart_secure_listeners do
    listen = Application.get_env(:xturn, :listen, [])

    for spec <- listen, secure?(spec) do
      id = listener_id(spec)

      with :ok <- terminate_listener(id),
           {:ok, _} <- Supervisor.restart_child(__MODULE__, id) do
        :ok
      else
        {:error, :not_found} -> :ok
        {:error, reason} -> require Logger; Logger.warning("could not restart #{id}: #{inspect(reason)}")
      end
    end

    :ok
  end

  @doc false
  def init([list]) do
    cert_children =
      if Enum.any?(list, &secure?/1) do
        [start_child(Watcher), start_child(SignalHandler.Registrar)]
      else
        []
      end

    children =
      cert_children ++
        [
          start_child(Server),
          start_child(PacketLog.Writer),
          start_child(ClientWorker.Pool),
          start_child(Xirsys.XTurn.RelayIngress),
          start_child(Plugin.Supervisor),
          %{
            id: Allocate.Supervisor,
            start: {Allocate.Supervisor, :start_link, [Allocate.Client]}
          },
          start_child(Auth.Supervisor),
          start_child(SockSupervisor, [[]]),
          start_child(TierSupervisor.Task, [[]]),
          start_child(TierSupervisor.Pool, [[]])
        ] ++ Enum.flat_map(list, &listener_children/1)

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp terminate_listener(id) do
    case Supervisor.terminate_child(__MODULE__, id) do
      :ok -> :ok
      {:error, :not_found} -> :ok
      other -> other
    end
  end

  defp secure?({_type, _ip, _port, :secure}), do: true
  defp secure?(_spec), do: false

  # First UDP shard registers in ListenRegistry (insert_new). Later
  # SO_REUSEPORT shards classify locally; CHANGE-REQUEST uses shard 0.
  defp listener_children({type, ip_str, port}),
    do: listener_children({type, ip_str, port, false})

  defp listener_children({type, ip_str, port, secure}) do
    if udp_reuseport_shards?(type, secure) do
      shards = udp_listen_shards()

      for index <- 0..(shards - 1) do
        listener_child_spec({type, ip_str, port, secure}, index, listen_opts: [reuseport: true])
      end
    else
      [listener_child_spec({type, ip_str, port, secure}, 0, [])]
    end
  end

  defp listener_child_spec({type, ip_str, port, secure}, index, extra_opts) do
    {:ok, ip} = :inet_parse.address(ip_str)
    secure? = secure == :secure
    {mod, transport} = listener_module(type, secure?)

    opts = [
      transport: transport,
      ip: ip,
      port: port,
      pipeline: pipeline_for(type),
      assigns: %{transport: transport}
    ] ++ extra_opts

    child_mod = if mod == DatagramServer, do: DatagramListener, else: mod
    Supervisor.child_spec({child_mod, opts}, id: listener_id({type, ip_str, port, secure}, index))
  end

  defp udp_reuseport_shards?(:udp, false), do: udp_listen_shards() > 1
  defp udp_reuseport_shards?(_, _), do: false

  defp udp_listen_shards do
    Application.get_env(:xturn, :udp_listen_shards, System.schedulers_online())
    |> max(1)
  end

  # ChannelData padding is mandatory on stream transports and optional on
  # datagram transports (RFC 5766, Section 11.5), so each gets its own pipeline.
  defp pipeline_for(:udp), do: SocketPipeline.Datagram
  defp pipeline_for(:tcp), do: SocketPipeline

  defp listener_module(:udp, false), do: {DatagramServer, Transport.UDP}
  defp listener_module(:udp, true), do: {Acceptor, Transport.DTLS}
  defp listener_module(:tcp, false), do: {Acceptor, Transport.TCP}
  defp listener_module(:tcp, true), do: {Acceptor, Transport.TLS}

  defp listener_id({type, ip_str, port, secure}, index \\ 0) do
    suffix = if secure == :secure, do: "secure_", else: ""

    ip_tag =
      ip_str
      |> List.to_string()
      |> String.replace(":", "_")
      |> String.replace(".", "_")

    shard = if index == 0, do: "", else: "_shard#{index}"
    :"#{type}_listener_#{suffix}#{ip_tag}_#{port}#{shard}"
  end

  defp start_child(mod, args \\ []) do
    %{
      id: mod,
      start: {mod, :start_link, args}
    }
  end
end
