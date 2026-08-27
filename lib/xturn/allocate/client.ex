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

defmodule Xirsys.XTurn.Allocate.Client do
  @moduledoc """
  GenServer owning one TURN allocation (relay, permissions, channels, TCP relay).

  ## What problem this solves

  After a successful Allocate, the client needs a relay address on the server,
  permission to send to peer IPs, optional channel bindings for efficient
  media, and periodic Refresh to keep the allocation alive. One GenServer per
  allocation holds relay sockets, timed permissions/channels, byte counters, and
  the client `%ClientSocket{}` so control and data paths share consistent state.

  ## Internal note

  Started by `Allocate.Supervisor`; indexed in `Allocate.Store` for fast lookup.
  Operators interact via STUN/TURN and REST, not this module's functions.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (allocation, permissions, channels, Refresh)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (address families, even-port reservation)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TCP relay, Connect, ConnectionBind)
  """
  use GenServer
  require Logger
  @vsn "0"

  @default_lifetime 600
  @channel_lifetime 600_000
  @permission_lifetime 300_000
  @bind_timeout_ms 30_000

  alias Xirsys.XTurn.Allocate.{Quota, Store, Client, TcpRegistry}
  alias Xirsys.XTurn.AddressFamily
  alias Xirsys.XTurn.Tuple5, as: T5
  alias Xirsys.XTurn.Channels.Store, as: Channels
  alias Xirsys.XTurn.Channels.Channel
  alias Xirsys.XTurn.Permissions.Store, as: Permissions
  alias Xirsys.XTurn.TimedEntry
  alias Xirsys.XTurn.Allocate.Bytes
  alias Xirsys.XTurn.{ClientSocket, PeerFilter, RelayPort, StunHelper}
  alias XSockets.Transport.{TCP, UDP}
  alias Xirsys.XTurn.Timing, as: Time
  alias XSockets.Config

  defmodule State do
    @moduledoc """
    In-process state for one `Allocate.Client` GenServer.

    ## What problem this solves

    Each TURN allocation is a GenServer that must track the client socket,
    relay ports, permissions, channels, credentials, and lifetime deadline in
    one place. This struct is that process state.

    ## Internal

    Not exposed to operators; mutated only inside the allocation process.

    ## RFCs

    - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (allocation state, permissions, channels)
    - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TCP allocations / ConnectionBind)
    """

    @typedoc """
    Allocation GenServer state.

    ## Fields

    - `:id` - allocation transaction id / `Store` key
    - `:client_socket` - `%ClientSocket{}` for replies and indications to the client
    - `:tuple5` - client/server five-tuple identifying this allocation
    - `:relayed_address` - primary XOR-RELAYED-ADDRESS `{ip, port}` (legacy single relay)
    - `:relayed_socket` - primary relay UDP port (legacy)
    - `:relays` - map `family => %{socket, address, port}` for multi-family relays
    - `:tcp_listen` - RFC 6062 inbound TCP listen socket
    - `:tcp_family` - address family integer for the TCP listen socket
    - `:connections` - map of pending/active RFC 6062 outbound connections by connection id
    - `:peer_connections` - map of peer `{ip, port}` to connection id
    - `:requested_transport` - `:udp` or `:tcp` from Allocate REQUESTED-TRANSPORT
    - `:dont_fragment` - when true, set IP DF on cross-family UDP relay sends
    - `:recv_meta` - platform recv metadata (e.g. IP_PKTINFO) for relay sends
    - `:reserve_port` - EVEN-PORT reservation requested at allocate
    - `:next_port` - RESERVATION-TOKEN follow-up allocate flag
    - `:username`, `:passhash`, `:nonce` - long-term credentials bound to this allocation
    - `:refresh_time` - allocation start as Gregorian seconds (legacy reporting)
    - `:lifetime` - current lifetime in seconds
    - `:deadline_ms` - monotonic expiry deadline from `Timing.deadline_ms/1`
    - `:permissions` - `TimedEntry` map of peer IP to permission timer
    - `:channels` - `TimedEntry` map of channel number to `%Channel{}`
    - `:peer_to_channel` - map `{ip, port}` to bound channel number
    - `:bytes_in`, `:bytes_out` - relay byte totals (merged from `Allocate.Bytes`)
    - `:peer_started`, `:peer_ended` - billing/session timestamps
    - `:peer_id`, `:ns` - external metadata namespace and peer id
    - `:last_responses` - cached success attrs for idempotent STUN retransmits
    """
    @vsn "0"
    defstruct id: nil,
              client_socket: nil,
              tuple5: nil,
              relayed_address: nil,
              relayed_socket: nil,
              relays: %{},
              tcp_listen: nil,
              tcp_family: nil,
              connections: %{},
              peer_connections: %{},
              requested_transport: :udp,
              dont_fragment: false,
              recv_meta: %{},
              reserve_port: false,
              next_port: false,
              username: nil,
              passhash: nil,
              nonce: nil,
              refresh_time: nil,
              lifetime: 600,
              deadline_ms: nil,
              permissions: nil,
              channels: nil,
              peer_to_channel: %{},
              bytes_in: 0,
              bytes_out: 0,
              peer_started: nil,
              peer_ended: nil,
              peer_id: nil,
              ns: nil,
              last_responses: %{}

    @type t :: %__MODULE__{
            id: term(),
            client_socket: Xirsys.XTurn.ClientSocket.t() | nil,
            tuple5: Xirsys.XTurn.Tuple5.t() | nil,
            relayed_address: {:inet.ip_address(), :inet.port_number()} | nil,
            relayed_socket: port() | nil,
            relays: map(),
            tcp_listen: port() | nil,
            tcp_family: integer() | nil,
            connections: map(),
            peer_connections: map(),
            requested_transport: :udp | :tcp,
            dont_fragment: boolean(),
            recv_meta: map(),
            reserve_port: boolean(),
            next_port: boolean(),
            username: binary() | nil,
            passhash: binary() | nil,
            nonce: binary() | nil,
            refresh_time: integer() | nil,
            lifetime: pos_integer(),
            deadline_ms: integer() | nil,
            permissions: map() | nil,
            channels: map() | nil,
            peer_to_channel: map(),
            bytes_in: non_neg_integer(),
            bytes_out: non_neg_integer(),
            peer_started: term(),
            peer_ended: term(),
            peer_id: term(),
            ns: term(),
            last_responses: map()
          }
  end

  #########################################################################################################################
  # Interface functions
  #########################################################################################################################

  @doc """
  Starts an allocation GenServer linked to the caller.

  `id` is the allocation key in `Store`. `tuple5` identifies the client
  five-tuple; `lifetime` is the initial refresh interval in seconds.
  """
  def start_link(id, client_socket, tuple5, lifetime),
    do: GenServer.start_link(__MODULE__, [id, client_socket, tuple5, lifetime])

  @doc """
  Starts an allocation under `Allocate.Supervisor` with explicit `lifetime` (seconds).
  """
  def create(id, client_socket, tuple5, lifetime),
    do: Xirsys.XTurn.Allocate.Supervisor.start_child(id, client_socket, tuple5, lifetime)

  @doc """
  Starts an allocation under `Allocate.Supervisor` with default lifetime (#{@default_lifetime}s).
  """
  def create(id, client_socket, tuple5),
    do: create(id, client_socket, tuple5, @default_lifetime)

  @doc "Stops the allocation process gracefully (`:normal` reason)."
  def destroy(pid) do
    GenServer.stop(pid, :normal, :infinity)
  catch
    :exit, _ -> :ok
  end

  @doc "Refreshes allocation lifetime; `lifetime` 0 triggers deallocation."
  def refresh(pid, lifetime),
    do: GenServer.cast(pid, {:refresh, lifetime})

  @doc "Returns `{:ok, count}` of running allocation workers from the supervisor."
  def count() do
    pid = Process.whereis(Xirsys.XTurn.Allocate.Supervisor)
    %{workers: workers} = Supervisor.count_children(pid)
    {:ok, workers}
  end

  @doc "Opens a relay UDP port on `bind_ip` using an ephemeral (random) port."
  def open_port_random(pid, bind_ip, opts \\ []),
    do: GenServer.call(pid, {:open_port, :random, bind_ip, opts})

  @doc "Opens a relay UDP port, preferring `port` on `bind_ip`."
  def open_port_preferred(pid, port, bind_ip, opts \\ []),
    do: GenServer.call(pid, {:open_port, {:preferred, port}, bind_ip, opts})

  @doc "Opens a relay UDP port in `[min, max]` on `bind_ip`."
  def open_port_range(pid, min, max, bind_ip, opts \\ []),
    do: GenServer.call(pid, {:open_port, {:range, min, max}, bind_ip, opts})

  @doc "Returns `{:ok, permissions_map}` of active permission entries."
  def get_permission_cache(pid),
    do: GenServer.call(pid, :get_permission_cache)

  @doc "Associates billing/metadata namespace `ns` and `peer_id` with the allocation."
  def set_peer_details(pid, ns, peer_id),
    do: GenServer.cast(pid, {:set_peer_details, ns, peer_id})

  @doc "Sets IP_DF (don't fragment) on the primary relay socket; may return `:not_supported`."
  def dont_fragment(pid),
    do: GenServer.call(pid, :dont_fragment)

  @doc "Clears IPv4 header checksum field on the relay socket (platform-specific)."
  def clear_header(pid),
    do: GenServer.call(pid, :clear_header)

  @doc "Records the primary relayed transport address (cast, no reply)."
  def set_relay_address(pid, relay_address),
    do: GenServer.cast(pid, {:relay_address, relay_address})

  @doc "Grants permission for `peer_ip` (creates/refreshes timed permission entry)."
  def add_permissions(pid, peer_ip) when is_tuple(peer_ip),
    do: GenServer.call(pid, {:add_permissions, peer_ip})

  @doc "Returns the allocation `id` string/key."
  def get_id(pid), do: GenServer.call(pid, :get_id)

  @doc "Returns current lifetime in seconds."
  def get_lifetime(pid), do: GenServer.call(pid, :get_lifetime)

  @doc "Returns `{username, passhash}` credentials stored on the allocation."
  def get_credentials(pid), do: GenServer.call(pid, :get_credentials)

  @doc "Stores TURN long-term credentials on the allocation."
  def set_credentials(pid, username, passhash),
    do: GenServer.cast(pid, {:set_credentials, username, passhash})

  @doc "Enables don't-fragment behaviour for cross-family UDP relay."
  def enable_dont_fragment(pid),
    do: GenServer.cast(pid, :enable_dont_fragment)

  @doc """
  Completes RFC 6062 ConnectionBind: hands `peer_socket` to `owner_pid`.

  `connection_id` must match a pending inbound/outbound TCP connection.
  Returns `{:ok, peer_socket}` or `{:error, :not_found}`.
  """
  def connection_bind(pid, connection_id, client_socket, owner_pid),
    do: GenServer.call(pid, {:connection_bind, connection_id, client_socket, owner_pid})

  @doc "Registers `socket` as the relay socket for address family `family`."
  def assign_relay_socket(pid, socket, family),
    do: GenServer.call(pid, {:assign_relay_socket, socket, family})

  @doc """
  Publishes per-family relay `{socket, address}` map to `Store`.

  `relays` is `{family => {socket, port, address}}`.
  """
  def set_relay_addresses(pid, relays),
    do: GenServer.call(pid, {:set_relay_addresses, relays})

  @doc "Returns list of relay transport addresses for all active families."
  def get_relay_addresses(pid),
    do: GenServer.call(pid, :get_relay_addresses)

  @doc "Returns address family integers (e.g. `4`, `8`) with active relays."
  def active_families(pid),
    do: GenServer.call(pid, :active_families)

  @doc "Returns `:udp` or `:tcp` as requested at allocation time."
  def requested_transport(pid),
    do: GenServer.call(pid, :requested_transport)

  @doc """
  Opens an outbound TCP connection to `peer` (RFC 6062 Connect).

  Returns `{:ok, connection_id}` or `{:error, :exists}` / `{:error, :timeout}`.
  """
  def tcp_connect(pid, peer),
    do: GenServer.call(pid, {:tcp_connect, peer})

  @doc "Assigns TCP listen socket for inbound peer connections on `family`."
  def assign_tcp_listen(pid, listen, family),
    do: GenServer.call(pid, {:assign_tcp_listen, listen, family})

  @doc "Caches success response attributes for idempotent retransmits."
  def cache_response(pid, method, transactionid, attrs),
    do: GenServer.cast(pid, {:cache_response, method, transactionid, attrs})

  @doc "Returns cached attrs for `{method, transactionid}`, or `nil`."
  def cached_response(pid, method, transactionid),
    do: GenServer.call(pid, {:cached_response, method, transactionid})

  @doc """
  Opens an even UDP port (RFC 5766 EVEN-PORT / RESERVATION-TOKEN).

  When `reserve_next?` is true, reserves the following odd port as well.
  Returns `{:ok, socket, port, token}` or `{:error, reason}`.
  """
  def open_even_port(pid, reserve_next?, bind_ip, opts \\ []),
    do: GenServer.call(pid, {:open_even_port, reserve_next?, bind_ip, opts})

  @doc """
  Binds `channel_number` to `peer_address` (RFC 5766 ChannelBind).

  Returns `:ok` or `{:error, :conflict}`.
  """
  def bind_channel(pid, channel_number, peer_address),
    do: GenServer.call(pid, {:bind_channel, channel_number, peer_address})

  @doc """
  Refreshes permission (and optional channel) from live relay traffic.

  Casts so the media path never blocks.
  """
  def touch(pid, peer_ip, channel \\ nil)

  def touch(pid, peer_ip, channel) when is_pid(pid) and is_tuple(peer_ip) do
    GenServer.cast(pid, {:touch, peer_ip, channel})
    :ok
  end

  @doc "Removes channel binding `channel_number`."
  def remove_peer_channel(pid, channel_number, _peer_address),
    do: GenServer.call(pid, {:remove_channel, channel_number})

  @doc "Refreshes channel lifetime for `id` (channel number)."
  def refresh_channel(pid, id),
    do: GenServer.cast(pid, {:refresh_channel, id})

  @doc """
  Sends `data` on `channel` to the bound peer.

  When `socket` and `peer_address` are provided, sends synchronously on the
  fast path without a GenServer cast. Otherwise queues `{:send_channel, ...}`.
  """
  def send_channel(pid, channel, data, socket \\ nil, peer_address \\ nil)

  def send_channel(pid, channel, <<_::binary>> = data, _, nil) when is_integer(channel),
    do: GenServer.cast(pid, {:send_channel, channel, data})

  def send_channel(_pid, channel, <<_::binary>> = data, socket, {_, _} = peer_address)
      when is_integer(channel) do
    send_data_channel(data, peer_address, socket)
    :ok
  end

  @doc """
  Relays `data` to `{pip, pport}` via `socket` and updates byte counters.

  Used by the media fast path when socket and peer are already resolved.
  """
  def relay_to_peer(pid, {pip, pport}, <<_::binary>> = data, socket) do
    send_data(data, pip, pport, socket)
    Bytes.add_out(pid, byte_size(data))
    :ok
  end

  @doc """
  Sends a Send indication payload to `peer_address`.

  With `socket` and `perms` set, checks permissions and sends on the fast path.
  Otherwise casts to the GenServer for permission-gated UDP send.
  """
  def send_indication(pid, peer_address, data, socket \\ nil, perms \\ nil)

  def send_indication(pid, {_, _} = peer_address, <<_::binary>> = data, nil, _perms),
    do: GenServer.cast(pid, {:send_indication, peer_address, data})

  def send_indication(_pid, {pip, pport}, <<_::binary>> = data, socket, perms) do
    cond do
      not require_perms() or permission_allowed?(perms, pip) ->
        Client.send_data(data, pip, pport, socket)
        :ok

      true ->
        :ok
    end
  end

  #########################################################################################################################
  # OTP functions
  #########################################################################################################################

  @impl true
  @doc false
  def init([id, client_socket, tuple5, lifetime]) do
    Bytes.register(self())

    {:ok,
     %State{
       id: id,
       client_socket: client_socket,
       tuple5: tuple5,
       requested_transport: transport_from_tuple5(tuple5),
       refresh_time: Time.now(),
       lifetime: lifetime,
       deadline_ms: Time.deadline_ms(lifetime),
       peer_started: Time.local_time(),
       permissions: %{},
       channels: %{}
     }, Time.milliseconds_left(%{deadline_ms: Time.deadline_ms(lifetime)})}
  end

  @impl true
  @doc false
  def handle_info(:timeout, %State{} = state),
    do: {:stop, :normal, state}

  @doc false
  def handle_info(:start_tcp_accept, %State{tcp_listen: listen} = state) when not is_nil(listen) do
    Process.send(self(), {:tcp_accept, listen}, [])
    {:noreply, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_info({:tcp_accept, listen}, %State{} = state) do
    case TCP.accept(listen, 0) do
      {:ok, socket} ->
        {:noreply, handle_inbound_peer_tcp(socket, state), Time.milliseconds_left(state)}

      {:error, :timeout} ->
        Process.send(self(), {:tcp_accept, listen}, [])
        {:noreply, state, Time.milliseconds_left(state)}

      {:error, _} ->
        Process.send_after(self(), {:tcp_accept, listen}, 100)
        {:noreply, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_info({:tcp, socket, data}, %State{} = state) do
    case find_connection_by_socket(state.connections, socket) do
      {connection_id, %{status: :pending} = entry} ->
        buffer = entry.buffer ++ [data]
        connections = Map.put(state.connections, connection_id, %{entry | buffer: buffer})
        :inet.setopts(socket, active: :once)
        {:noreply, %State{state | connections: connections}, Time.milliseconds_left(state)}

      _ ->
        :gen_tcp.close(socket)
        {:noreply, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_info({:tcp_closed, socket}, %State{} = state) do
    case find_connection_by_socket(state.connections, socket) do
      {connection_id, entry} ->
        {:noreply, drop_connection(state, connection_id, entry), Time.milliseconds_left(state)}

      _ ->
        {:noreply, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_info({:bind_timeout, connection_id}, %State{} = state) do
    case Map.get(state.connections, connection_id) do
      %{peer_socket: socket} = entry ->
        if is_port(socket), do: :gen_tcp.close(socket)
        {:noreply, drop_connection(state, connection_id, entry), Time.milliseconds_left(state)}

      _ ->
        {:noreply, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_info({:udp, _socket, _ip, _in_port, _packet}, %State{} = state) do
    {:noreply, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_info({:udp_error, _socket, reason}, %State{} = state) do
    case XSockets.Transport.UDP.handle_message({:udp_error, nil, reason}, nil) do
      {:icmp, %{type: type, code: code, error_data: error_data, peer: peer}} ->
        {ip, port} = peer
        data = StunHelper.icmp_indication({ip, port}, type, code, error_data)
        ClientSocket.send(state.client_socket, data)
        {:noreply, state, Time.milliseconds_left(state)}

      _ ->
        {:noreply, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_info({:permission_expired, ip}, %State{} = state) do
    if Permissions.due_refresh?(state.tuple5, ip, @permission_lifetime) do
      permissions = TimedEntry.remove(state.permissions, ip)
      Permissions.revoke(state.tuple5, ip)
      {:noreply, %State{state | permissions: permissions}, Time.milliseconds_left(state)}
    else
      {:noreply, put_permission(state, ip), Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_info({:channel_expired, channel_number}, %State{} = state) do
    case Map.get(state.channels, channel_number) do
      {ref, _} when is_reference(ref) ->
        if is_integer(Process.read_timer(ref)) do
          {:noreply, state, Time.milliseconds_left(state)}
        else
          {:noreply, do_unbind_channel(state, channel_number), Time.milliseconds_left(state)}
        end

      _ ->
        {:noreply, do_unbind_channel(state, channel_number), Time.milliseconds_left(state)}
    end
  end

  @impl true
  @doc false
  def handle_call({:open_port, policy, bind_ip, opts}, _from, %State{} = state),
    do: open_port_call({policy, bind_ip, opts}, state)

  @doc false
  def handle_call(:get_relay_addresses, _from, %State{} = state) do
    addresses =
      state.relays
      |> Map.values()
      |> Enum.map(& &1.address)

    {:reply, addresses, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call(:active_families, _from, %State{} = state) do
    families =
      state.relays
      |> Map.keys()
      |> then(fn keys ->
        if state.tcp_listen && state.tcp_family, do: [state.tcp_family | keys], else: keys
      end)
      |> Enum.uniq()

    {:reply, families, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call(:requested_transport, _from, %State{} = state) do
    {:reply, state.requested_transport, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:cached_response, method, transactionid}, _from, %State{} = state) do
    {:reply, Map.get(state.last_responses, {method, transactionid}), state,
     Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call(:get_permission_cache, _from, %State{} = state),
    do: {:reply, {:ok, state.permissions}, state, Time.milliseconds_left(state)}

  @doc false
  def handle_call(:get_id, _from, %State{} = state),
    do: {:reply, state.id, state, Time.milliseconds_left(state)}

  @doc false
  def handle_call(:get_lifetime, _from, %State{} = state),
    do: {:reply, state.lifetime, state, Time.milliseconds_left(state)}

  @doc false
  def handle_call(:get_credentials, _from, %State{} = state),
    do: {:reply, {state.username, state.passhash}, state, Time.milliseconds_left(state)}

  @doc false
  def handle_call({:tcp_connect, {ip, port} = peer}, _from, %State{} = state) do
    if Map.has_key?(state.peer_connections, peer) do
      {:reply, {:error, :exists}, state, Time.milliseconds_left(state)}
    else
      connect_opts = relay_connect_opts(state)

      case TCP.connect(ip, port, connect_opts) do
        {:ok, socket} ->
          connection_id = :crypto.strong_rand_bytes(4)
          timer = schedule_bind_timeout(connection_id)

          conn_entry = %{
            peer: peer,
            peer_socket: socket,
            status: :pending,
            buffer: [],
            timer: timer,
            direction: :outbound
          }

          connections = Map.put(state.connections, connection_id, conn_entry)
          peer_connections = Map.put(state.peer_connections, peer, connection_id)
          :ok = TcpRegistry.register(connection_id, self())
          :inet.setopts(socket, [:binary, active: :once])

          {:reply, {:ok, connection_id},
           %State{state | connections: connections, peer_connections: peer_connections},
           Time.milliseconds_left(state)}

        {:error, _} ->
          {:reply, {:error, :timeout}, state, Time.milliseconds_left(state)}
      end
    end
  end

  @doc false
  def handle_call({:connection_bind, connection_id, _client_socket, owner_pid}, _from, %State{} = state) do
    case Map.get(state.connections, connection_id) do
      %{peer_socket: peer_socket, status: :pending, timer: timer, buffer: buffer} = entry ->
        if timer, do: Process.cancel_timer(timer)
        TcpRegistry.unregister(connection_id)

        for data <- buffer, do: :gen_tcp.send(peer_socket, data)

        _ = :gen_tcp.controlling_process(peer_socket, owner_pid)

        connections = Map.delete(state.connections, connection_id)
        peer_connections = Map.delete(state.peer_connections, entry.peer)

        {:reply, {:ok, peer_socket},
         %State{state | connections: connections, peer_connections: peer_connections},
         Time.milliseconds_left(state)}

      _ ->
        {:reply, {:error, :not_found}, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_call({:assign_tcp_listen, listen, family}, _from, %State{} = state) do
    send(self(), :start_tcp_accept)

    {:reply, :ok,
     %State{state | tcp_listen: listen, tcp_family: family, requested_transport: :tcp},
     Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:assign_relay_socket, socket, family}, _from, %State{} = state) do
    relays = Map.put(state.relays, family, %{socket: socket, address: nil, family: family})
    {:reply, :ok, put_primary_relay(%State{state | relays: relays, relayed_socket: socket}),
     Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:open_even_port, reserve_next?, bind_ip, opts}, _from, %State{} = state) do
    case RelayPort.open_even(bind_ip, reserve_next?, opts) do
      {:ok, socket, port, token} ->
        {:reply, {:ok, socket, port, token}, %State{state | relayed_socket: socket},
         Time.milliseconds_left(state)}

      {:error, reason} ->
        {:reply, {:error, reason}, state, Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_call(:dont_fragment, _from, %State{} = state) do
    res =
      case UDP.set_dont_fragment(state.relayed_socket) do
        :ok -> :ok
        {:error, :not_supported} -> {:error, :not_supported}
      end

    {:reply, res, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call(:clear_header, _from, %State{} = state) do
    res = :inet.setopts(state.relayed_socket, [{:raw, 0, 10, <<0::native-size(32)>>}])
    {:reply, res, state, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:bind_channel, channel_number, peer_address}, _from, %State{} = state) do
    bound_channel_for_peer = Map.get(state.peer_to_channel, peer_address)
    channel_in_use_by_other_peer? = channel_bound_to_a_peer?(state.peer_to_channel, channel_number)

    cond do
      bound_channel_for_peer == channel_number ->
        state =
          state
          |> refresh_channel_entry(channel_number)
          |> refresh_permission(peer_address)

        {:reply, :ok, state, Time.milliseconds_left(state)}

      bound_channel_for_peer != nil or channel_in_use_by_other_peer? ->
        {:reply, {:error, :conflict}, state, Time.milliseconds_left(state)}

      true ->
        {:reply, :ok, do_bind_channel(state, channel_number, peer_address),
         Time.milliseconds_left(state)}
    end
  end

  @doc false
  def handle_call({:remove_channel, channel_number}, _from, %State{} = state) do
    {:reply, :ok, do_unbind_channel(state, channel_number), Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:remove_permission, id}, _from, %State{} = state) do
    permissions = TimedEntry.remove(state.permissions, id)
    Permissions.revoke(state.tuple5, id)
    {:reply, :ok, %State{state | permissions: permissions}, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:add_permissions, perm}, _from, %State{} = state) do
    {:reply, :ok, put_permission(state, perm), Time.milliseconds_left(state)}
  end

  @doc false
  def handle_call({:set_relay_addresses, relays}, _from, %State{} = state) do
    relays =
      Map.new(relays, fn {fam, {socket, _port, address}} ->
        family = Map.get(state.relays, fam, %{}) |> Map.get(:family, fam)
        {fam, %{socket: socket, address: address, family: family}}
      end)

    state = put_primary_relay(%State{state | relays: relays})

    Store.publish_relays(
      self(),
      state.client_socket,
      state.peer_to_channel,
      state.tuple5,
      relays
    )

    {:reply, :ok, state, Time.milliseconds_left(state)}
  end

  @impl true
  @doc false
  def handle_cast(:enable_dont_fragment, %State{} = state),
    do: {:noreply, %State{state | dont_fragment: true}, Time.milliseconds_left(state)}

  @doc false
  def handle_cast({:set_credentials, username, passhash}, %State{} = state),
    do: {:noreply, %State{state | username: username, passhash: passhash}, Time.milliseconds_left(state)}

  @doc false
  def handle_cast({:cache_response, method, transactionid, attrs}, %State{} = state) do
    {:noreply,
     %State{
       state
       | last_responses: Map.put(state.last_responses, {method, transactionid}, attrs)
     }, Time.milliseconds_left(state)}
  end

  @doc false
  def handle_cast({:set_peer_details, ns, peer_id}, %State{} = state),
    do: {:noreply, %State{state | ns: ns, peer_id: peer_id}, Time.milliseconds_left(state)}

  @doc false
  def handle_cast({:relay_address, relay_address}, %State{} = state),
    do: {:noreply, %State{state | relayed_address: relay_address}, Time.milliseconds_left(state)}

  @doc false
  def handle_cast({:refresh, 0}, %State{} = state), do: {:stop, :normal, state}

  @doc false
  def handle_cast({:refresh, lifetime}, %State{} = state) when is_integer(lifetime) do
    deadline_ms = Time.deadline_ms(lifetime)

    {:noreply,
     %State{state | refresh_time: Time.now(), lifetime: lifetime, deadline_ms: deadline_ms},
     Time.milliseconds_left(%{deadline_ms: deadline_ms})}
  end

  @doc false
  def handle_cast({:refresh_family, family, lifetime}, %State{} = state) do
    if lifetime == 0 do
      close_relay_family(state, family)
    else
      deadline_ms = Time.deadline_ms(lifetime)

      {:noreply, %State{state | refresh_time: Time.now(), deadline_ms: deadline_ms},
       Time.milliseconds_left(%{deadline_ms: deadline_ms})}
    end
  end

  @doc false
  def handle_cast({:refresh_channel, id}, %State{} = state) do
    {:noreply, refresh_channel_entry(state, id), Time.milliseconds_left(state)}
  end

  @doc false
  def handle_cast({:touch, peer_ip, channel}, %State{} = state) do
    state = put_permission(state, peer_ip)
    state = refresh_channel_entry(state, channel)
    deadline_ms = Time.deadline_ms(state.lifetime)

    {:noreply, %State{state | deadline_ms: deadline_ms, refresh_time: Time.now()},
     Time.milliseconds_left(%{deadline_ms: deadline_ms})}
  end

  @doc false
  def handle_cast({:send_channel, channel_number, data}, %State{} = state) do
    bytes_out =
      case TimedEntry.fetch(state.channels, channel_number) do
        {:ok, %Channel{peer_address: peer_address}} ->
          send_data_channel(data, peer_address, relay_socket_for_peer(state, peer_address), state)

        :error ->
          0
      end

    {:noreply, %State{state | bytes_out: state.bytes_out + bytes_out},
     Time.milliseconds_left(state)}
  end

  @doc false
  def handle_cast({:send_indication, {pip, pport} = _peer_address, data}, %State{} = state) do
    with true <- TimedEntry.has_key?(state.permissions, pip) do
      send_data(data, pip, pport, state)

      {:noreply, %State{state | bytes_out: state.bytes_out + byte_size(data)},
       Time.milliseconds_left(state)}
    else
      _ ->
        {:noreply, state, Time.milliseconds_left(state)}
    end
  end

  @impl true
  @doc false
  def terminate(reason, state) do
    state = Bytes.merge(state, self())
    Bytes.unregister(self())

    Xirsys.XTurn.Plugin.Lifecycle.allocation_ended(state.tuple5, reason)
    Logger.info("Terminating with state : #{inspect(reason)}")

    for {_fam, %{socket: socket}} <- state.relays do
      if is_port(socket), do: :gen_udp.close(socket)
    end

    if state.tcp_listen, do: TCP.close(state.tcp_listen)

    for {_id, %{peer_socket: socket, timer: timer}} <- state.connections do
      if timer, do: Process.cancel_timer(timer)
      if is_port(socket), do: :gen_tcp.close(socket)
      :ok
    end

    for {connection_id, _} <- state.connections do
      TcpRegistry.unregister(connection_id)
    end

    if state.relayed_socket && map_size(state.relays) == 0,
      do: :gen_udp.close(state.relayed_socket)

    if is_binary(state.username), do: Quota.decrement(state.username)

    Channels.delete_all(state.tuple5)
    TimedEntry.cancel_all(state.channels)
    TimedEntry.cancel_all(state.permissions)
    Permissions.revoke_all(state.tuple5)
    Store.delete(state.id)
    :ok
  end

  #########################################################################################################################
  # Helper functions
  #########################################################################################################################

  defp open_port_call({policy, bind_ip, opts}, %State{} = state) do
    case RelayPort.open(bind_ip, policy, opts) do
      {:ok, socket} ->
        {:ok, port} = :inet.port(socket)

        {:reply, {:ok, socket, port}, %State{state | relayed_socket: socket},
         Time.milliseconds_left(state)}

      {:error, reason} ->
        {:reply, {:error, reason}, state, Time.milliseconds_left(state)}
    end
  end

  defp put_primary_relay(%State{} = state) do
    case state.relays do
      %{4 => %{socket: socket, address: address}} ->
        %State{state | relayed_socket: socket, relayed_address: address}

      relays when map_size(relays) > 0 ->
        {_fam, %{socket: socket, address: address}} = relays |> Enum.min_by(fn {k, _} -> k end)
        %State{state | relayed_socket: socket, relayed_address: address}

      _ ->
        state
    end
  end

  defp relay_socket_for_peer(%State{} = state, {peer_ip, _}) do
    fam = AddressFamily.family_of(peer_ip)

    case Map.get(state.relays, fam) do
      %{socket: socket} -> socket
      _ -> state.relayed_socket
    end
  end

  defp close_relay_family(%State{} = state, family) do
    case Map.get(state.relays, family) do
      %{socket: socket} when is_port(socket) -> :gen_udp.close(socket)
      _ -> :ok
    end

    relays = Map.delete(state.relays, family)

    permissions =
      Enum.reduce(TimedEntry.keys(state.permissions), state.permissions, fn ip, perms ->
        if AddressFamily.family_of(ip) == family do
          Permissions.revoke(state.tuple5, ip)
          TimedEntry.remove(perms, ip)
        else
          perms
        end
      end)

    peer_to_channel =
      state.peer_to_channel
      |> Enum.reject(fn {{ip, _}, _} -> AddressFamily.family_of(ip) == family end)
      |> Map.new()

    if map_size(relays) == 0 do
      {:stop, :normal,
       %State{state | relays: relays, peer_to_channel: peer_to_channel, permissions: permissions}}
    else
      {:noreply,
       put_primary_relay(%State{
         state
         | relays: relays,
           peer_to_channel: peer_to_channel,
           permissions: permissions
       }), Time.milliseconds_left(state)}
    end
  end

  defp transport_from_tuple5(%T5{protocol: <<6, 0, 0, 0>>}), do: :tcp
  defp transport_from_tuple5(%T5{protocol: <<17, 0, 0, 0>>}), do: :udp
  defp transport_from_tuple5(_), do: :udp

  defp require_perms() do
    case Application.get_env(:xturn, :permissions) do
      %{required: required} -> required
      _ -> true
    end
  end

  @doc """
  Sends `msg` to the allocation's client using state-derived client address.

  ## Parameters

    * `msg` - encoded STUN or ChannelData binary
    * `state` - allocation `%State{}`
  """
  def send_data(msg, state) do
    t5 = state.tuple5
    send_data(msg, t5.client_address, t5.client_port, state)
  end

  @doc """
  Sends `msg` to a client or peer via `%ClientSocket{}`, a UDP port, or relay `%State{}`.
  """
  def send_data(msg, _cip, _cport, %ClientSocket{} = client) do
    ClientSocket.send(client, msg)
  end

  def send_data(msg, cip, cport, socket) when is_port(socket) do
    :gen_udp.send(socket, cip, cport, msg)
  end

  def send_data(msg, cip, cport, %State{} = state) do
    socket = relay_socket_for_peer(state, {cip, cport})
    relay_send(socket, msg, cip, cport, state)
  end

  @doc """
  Sends channel payload to a peer via the relay socket (fast path, no GenServer cast).

  ## Parameters

    * `data` - channel payload
    * `peer_address` - `{ip, port}` peer tuple
    * `socket` - relay UDP port
    * `state` - optional `%State{}` for DF/recv_meta; defaults to bare relay send
  """
  def send_data_channel(data, {pip, pport}, socket, state \\ nil) do
    if state do
      relay_send(socket, data, pip, pport, state)
    else
      relay_send(socket, data, pip, pport, %{dont_fragment: false, recv_meta: %{}})
    end

    byte_size(data)
  end

  defp channel_bound_to_a_peer?(peer_to_channel, channel_number),
    do: Enum.any?(peer_to_channel, fn {_peer, bound_channel} -> bound_channel == channel_number end)

  defp do_bind_channel(%State{} = state, channel_number, peer_address) do
    relayed_address = relay_address_for_peer(state, peer_address)
    channel = %Channel{id: channel_number, tuple5: state.tuple5, peer_address: peer_address}

    Channels.insert(
      channel_number,
      self(),
      peer_address,
      state.tuple5,
      relay_socket_for_peer(state, peer_address),
      relayed_address
    )

    channels =
      TimedEntry.put(
        state.channels,
        channel_number,
        channel,
        @channel_lifetime,
        self(),
        {:channel_expired, channel_number}
      )

    {peer_ip, _} = peer_address

    new_state =
      put_permission(
        %State{
          state
          | channels: channels,
            peer_to_channel: Map.put(state.peer_to_channel, peer_address, channel_number)
        },
        peer_ip
      )

    Store.update_peer_to_channel(self(), new_state.peer_to_channel)
    new_state
  end

  defp put_permission(%State{} = state, peer_ip) do
    Permissions.grant(state.tuple5, peer_ip)

    %State{
      state
      | permissions:
          TimedEntry.put(
            state.permissions,
            peer_ip,
            true,
            @permission_lifetime,
            self(),
            {:permission_expired, peer_ip}
          )
    }
  end

  defp refresh_permission(%State{} = state, {peer_ip, _port}) do
    put_permission(state, peer_ip)
  end

  defp refresh_channel_entry(%State{} = state, channel_number) when is_integer(channel_number) do
    case TimedEntry.fetch(state.channels, channel_number) do
      {:ok, value} when value != nil ->
        channels =
          TimedEntry.put(
            state.channels,
            channel_number,
            value,
            @channel_lifetime,
            self(),
            {:channel_expired, channel_number}
          )

        %State{state | channels: channels}

      _ ->
        state
    end
  end

  defp refresh_channel_entry(%State{} = state, _), do: state

  defp do_unbind_channel(%State{} = state, channel_number) do
    Channels.delete(channel_number, state.tuple5)

    channels = TimedEntry.remove(state.channels, channel_number)

    peer_to_channel =
      state.peer_to_channel
      |> Enum.reject(fn {_peer, bound_channel} -> bound_channel == channel_number end)
      |> Map.new()

    new_state = %State{state | channels: channels, peer_to_channel: peer_to_channel}
    Store.update_peer_to_channel(self(), new_state.peer_to_channel)
    new_state
  end

  defp permission_allowed?(perms, peer_ip) when is_map(perms),
    do: TimedEntry.has_key?(perms, peer_ip)

  defp permission_allowed?(_perms, _peer_ip), do: false

  defp relay_connect_opts(%State{tcp_listen: listen}) when not is_nil(listen) do
    case relay_bind_ip(listen) do
      nil -> []
      ip -> [ip: ip]
    end
  end

  defp relay_connect_opts(_), do: []

  defp relay_bind_ip(listen) do
    case :inet.sockname(listen) do
      {:ok, {{0, 0, 0, 0}, _port}} -> loopback_fallback(Config.server_ip())
      {:ok, {{0, 0, 0, 0, 0, 0, 0, 0}, _port}} -> loopback_fallback(Config.server_ip6())
      {:ok, {ip, _port}} -> ip
      _ -> nil
    end
  end

  defp loopback_fallback({0, 0, 0, 0}), do: {127, 0, 0, 1}
  defp loopback_fallback({0, 0, 0, 0, 0, 0, 0, 0}), do: {0, 0, 0, 0, 0, 0, 0, 1}
  defp loopback_fallback(ip), do: ip

  defp schedule_bind_timeout(connection_id) do
    Process.send_after(self(), {:bind_timeout, connection_id}, @bind_timeout_ms)
  end

  defp handle_inbound_peer_tcp(socket, %State{} = state) do
    case :inet.peername(socket) do
      {:ok, {ip, port}} ->
        peer = {ip, port}

        if require_perms() and not TimedEntry.has_key?(state.permissions, ip) do
          :gen_tcp.close(socket)
          Process.send(self(), {:tcp_accept, state.tcp_listen}, [])
          state
        else
          connection_id = :crypto.strong_rand_bytes(4)
          timer = schedule_bind_timeout(connection_id)

          conn_entry = %{
            peer: peer,
            peer_socket: socket,
            status: :pending,
            buffer: [],
            timer: timer,
            direction: :inbound
          }

          :ok = TcpRegistry.register(connection_id, self())

          data =
            StunHelper.connection_attempt_indication(peer, connection_id)

          ClientSocket.send(state.client_socket, data)

          connections = Map.put(state.connections, connection_id, conn_entry)
          peer_connections = Map.put(state.peer_connections, peer, connection_id)
          Process.send(self(), {:tcp_accept, state.tcp_listen}, [])

          %State{state | connections: connections, peer_connections: peer_connections}
          |> then(fn st ->
            :inet.setopts(socket, [:binary, active: :once])
            st
          end)
        end

      _ ->
        :gen_tcp.close(socket)
        Process.send(self(), {:tcp_accept, state.tcp_listen}, [])
        state
    end
  end

  defp find_connection_by_socket(connections, socket) do
    Enum.find_value(connections, fn {id, %{peer_socket: peer_socket} = entry} ->
      if peer_socket == socket, do: {id, entry}
    end)
  end

  defp drop_connection(%State{} = state, connection_id, entry) do
    if entry.timer, do: Process.cancel_timer(entry.timer)
    TcpRegistry.unregister(connection_id)

    %State{
      state
      | connections: Map.delete(state.connections, connection_id),
        peer_connections: Map.delete(state.peer_connections, entry.peer)
    }
  end

  @doc """
  Splices a TCP client socket to a peer socket (RFC 6062 data transfer).
  """
  def start_splice(client_socket, peer_socket) do
    splice_pid =
      spawn(fn ->
        for sock <- [client_socket, peer_socket] do
          :inet.setopts(sock, [:binary, active: :once, packet: :raw])
        end

        splice_loop(client_socket, peer_socket)
      end)

    _ = :gen_tcp.controlling_process(client_socket, splice_pid)
    _ = :gen_tcp.controlling_process(peer_socket, splice_pid)
    splice_pid
  end

  defp splice_loop(a, b) do
    receive do
      {:tcp, ^a, data} ->
        case :gen_tcp.send(b, data) do
          :ok -> :inet.setopts(a, active: :once)
          _ -> :gen_tcp.close(a)
        end

        splice_loop(a, b)

      {:tcp, ^b, data} ->
        case :gen_tcp.send(a, data) do
          :ok -> :inet.setopts(b, active: :once)
          _ -> :gen_tcp.close(b)
        end

        splice_loop(a, b)

      {:tcp_closed, sock} ->
        other = if sock == a, do: b, else: a
        if is_port(other), do: :gen_tcp.close(other)

      {:tcp_error, sock, _} ->
        other = if sock == a, do: b, else: a
        if is_port(other), do: :gen_tcp.close(other)
    end
  end

  defp relay_send(socket, data, peer_ip, peer_port, state) do
    if PeerFilter.forbidden?({peer_ip, peer_port}) do
      :ok
    else
      do_relay_send(socket, data, peer_ip, peer_port, state)
    end
  end

  defp do_relay_send(socket, data, peer_ip, peer_port, state) do
    peer_family = AddressFamily.family_of(peer_ip)
    relay_family = relay_family_for_socket(state, socket)

    if is_integer(relay_family) and peer_family != relay_family do
      meta = Map.get(state.recv_meta, {peer_ip, peer_port}, %{})

      ttl =
        case Map.get(meta, :ttl) do
          nil -> 64
          t when is_integer(t) -> max(t - 1, 1)
          _ -> 64
        end

      UDP.set_hop_limit(socket, ttl)

      if tos = Map.get(meta, :tos), do: UDP.set_tos(socket, tos)

      if peer_family == 8 and relay_family == 4 do
        UDP.set_flow_label(socket, Map.get(meta, :flow, 0))
      end

      if relay_family == 4 and peer_family == 8 and state.dont_fragment do
        UDP.set_dont_fragment(socket)
      end
    end

    :gen_udp.send(socket, peer_ip, peer_port, data)
  end

  defp relay_family_for_socket(state, socket) do
    relays = Map.get(state, :relays, %{})

    Enum.find_value(relays, fn {_fam, entry} ->
      case entry do
        %{socket: ^socket, family: family} -> family
        _ -> nil
      end
    end)
  end

  defp relay_address_for_peer(%State{} = state, {peer_ip, _}) do
    state.relays
    |> Map.get(AddressFamily.family_of(peer_ip), %{})
    |> Map.get(:address)
  end
end
