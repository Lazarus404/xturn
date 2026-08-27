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

defmodule Xirsys.XTurn.Actions.Allocate do
  @moduledoc """
  Pipeline action for TURN **Allocate** requests.

  ## What problem this solves

  A WebRTC client needs a relay address on the TURN server so media can flow
  when direct peer paths are blocked by NAT or firewalls. **Allocate** opens
  relay socket(s), starts an allocation worker, and returns XOR-RELAYED-ADDRESS
  plus lifetime to the client.

  Final step in the `@allocation` chain, after `HasRequestedTransport`,
  `NotAllocationExists`, and `Authenticates`.

  ## Internal

  Pipeline action only; not part of the public application API. Invoked by
  `Xirsys.XTurn.Pipeline` after earlier allocation guards succeed.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - TURN (Allocate, pt.6)
  * [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656) - TURN over TCP/TLS updates
  """
  require Logger
  alias XSockets.Config
  alias XSockets.Transport.UDP
  alias Xirsys.XTurn.AddressFamily
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.Allocate.{Quota, Store}
  alias Xirsys.XTurn.ReservationStore
  alias Xirsys.XTurn.Tuple5
  alias Xirsys.XTurn.Conn

  @udp_proto <<17, 0, 0, 0>>
  @tcp_proto <<6, 0, 0, 0>>
  @max_lifetime 600
  @dont_fragment_attr 26

  @doc """
  Creates relay socket(s) and an allocation worker, then registers the allocation.

  On success, returns conn with a success response (XOR-RELAYED-ADDRESS, lifetime).
  On failure, tears down any partial allocation and returns conn with an error response
  (400, 420, 440, 486, 508, or 300 Try Alternate).
  """
  def process(%Conn{decoded_message: %{attrs: attrs}} = conn) do
    Logger.debug("allocating #{inspect(conn.decoded_message)}")

    if Application.get_env(:xturn, :try_alternate, false) do
      Conn.response(conn, 300, "Try Alternate")
    else
      do_allocate(conn, attrs)
    end
  end

  defp do_allocate(conn, attrs) do
    proto = Map.get(attrs, :requested_transport)

    with :ok <- validate_allocate_attrs(attrs),
         :ok <- check_quota(attrs),
         lifetime <- requested_lifetime(attrs),
         {:ok, pid} <-
           AllocateClient.create(conn.decoded_message.transactionid, conn.client_socket, Tuple5.create(conn, proto), lifetime),
         {:ok, relays, extra_attrs} <- open_relays(conn, pid, attrs, proto),
         :ok <- apply_dont_fragment(relays, attrs, proto) do
      finish_allocate(conn, pid, attrs, lifetime, relays, extra_attrs, proto)
    else
      {:error, 400, msg} ->
        Conn.response(conn, 400, msg)

      {:error, 420, unknown} ->
        respond_unknown_required(conn, unknown)

      {:error, 440} ->
        Conn.response(conn, 440, "Address Family not Supported")

      {:error, 486} ->
        Conn.response(conn, 486, "Allocation Quota Reached")

      {:error, :reservation_token_invalid} ->
        Conn.response(conn, 508, "Insufficient Capacity")

      {:error, :insufficient_capacity} ->
        insufficient_capacity_response(conn)
    end
  end

  defp insufficient_capacity_response(conn) do
    if alternate_server?() do
      Conn.response(conn, 300, "Try Alternate")
    else
      Conn.response(conn, 508, "Insufficient Capacity")
    end
  end

  defp alternate_server?() do
    match?({ip, port} when is_tuple(ip) and is_integer(port), Application.get_env(:xturn, :alternate_server))
  end

  defp validate_allocate_attrs(attrs) do
    additional = Map.get(attrs, :additional_address_family)
    raf = Map.get(attrs, :requested_address_type)
    even_port = Map.get(attrs, :even_port)
    token = Map.get(attrs, :reservation_token)

    cond do
      token && even_port ->
        {:error, 400, "Bad Request"}

      token && raf ->
        {:error, 400, "Bad Request"}

      token && additional ->
        {:error, 400, "Bad Request"}

      raf && additional ->
        {:error, 400, "Bad Request"}

      additional == AddressFamily.ipv4() ->
        {:error, 400, "Bad Request"}

      even_port_reserve?(even_port) && additional ->
        {:error, 400, "Bad Request"}

      true ->
        :ok
    end
  end

  defp check_quota(attrs) do
    case Map.get(attrs, :username) do
      username when is_binary(username) ->
        case Quota.check(username) do
          :ok -> :ok
          {:error, 486} -> {:error, 486}
        end

      _ ->
        :ok
    end
  end

  defp requested_lifetime(attrs) do
    case Map.get(attrs, :lifetime) do
      <<n::32>> when n > @max_lifetime -> @max_lifetime
      <<n::32>> -> n
      _ -> @max_lifetime
    end
  end

  defp open_relays(_conn, pid, attrs, proto) do
    cond do
      Map.has_key?(attrs, :reservation_token) ->
        open_with_token(pid, attrs)

      AddressFamily.dual_additional?(attrs) ->
        open_dual(pid, attrs, proto)

      AddressFamily.ipv6_requested?(attrs) ->
        open_single(pid, attrs, proto, :v6)

      true ->
        open_single(pid, attrs, proto, :v4)
    end
  end

  defp open_with_token(pid, attrs) do
    token = Map.get(attrs, :reservation_token)

    case ReservationStore.claim(token) do
      {:ok, socket, port} ->
        case AllocateClient.assign_relay_socket(pid, socket, 4) do
          :ok ->
            relay = {Config.server_ip(), port}
            {:ok, %{4 => {socket, port, relay}}, %{}}

          _ ->
            :gen_udp.close(socket)
            fail_capacity(pid, :reservation_token_invalid)
        end

      :error ->
        fail_capacity(pid, :reservation_token_invalid)
    end
  end

  defp open_single(pid, attrs, proto, family) do
    if proto == @tcp_proto do
      open_tcp_single(pid, family)
    else
      open_udp_single(pid, attrs, family)
    end
  end

  defp open_udp_single(pid, attrs, family) do
    bind_ip = bind_ip(family)
    advertised = advertised_ip(family)
    fam = family_byte(family)

    cond do
      Map.has_key?(attrs, :even_port) ->
        reserve? = even_port_reserve?(Map.get(attrs, :even_port))

        case AllocateClient.open_even_port(pid, reserve?, bind_ip, []) do
          {:ok, socket, port, token} ->
            :ok = AllocateClient.assign_relay_socket(pid, socket, fam)
            relay = {advertised, port}
            extra = if token, do: %{reservation_token: token}, else: %{}
            {:ok, %{fam => {socket, port, relay}}, extra}

          {:error, _} ->
            if family == :v6, do: {:error, 440}, else: fail_capacity(pid, :insufficient_capacity)
        end

      true ->
        case AllocateClient.open_port_random(pid, bind_ip, []) do
          {:ok, socket, port} ->
            :ok = AllocateClient.assign_relay_socket(pid, socket, fam)
            relay = {advertised, port}
            {:ok, %{fam => {socket, port, relay}}, %{}}

          {:error, _} ->
            if family == :v6, do: {:error, 440}, else: fail_capacity(pid, :insufficient_capacity)
        end
    end
  end

  defp open_tcp_single(pid, family) do
    bind_ip = bind_ip(family)
    advertised = advertised_ip(family)
    fam = family_byte(family)

    case XSockets.Transport.TCP.listen(bind_ip, 0, []) do
      {:ok, listen} ->
        {:ok, {_, port}} = XSockets.Transport.TCP.sockname(listen)
        :ok = AllocateClient.assign_tcp_listen(pid, listen, fam)
        relay = {advertised, port}
        {:ok, %{fam => {listen, port, relay}}, %{}}

      {:error, _} ->
        if family == :v6, do: {:error, 440}, else: fail_capacity(pid, :insufficient_capacity)
    end
  end

  defp open_dual(pid, attrs, _proto) do
    v4 =
      if Map.has_key?(attrs, :even_port) do
        reserve? = even_port_reserve?(Map.get(attrs, :even_port))
        AllocateClient.open_even_port(pid, reserve?, Config.server_local_ip(), [])
      else
        AllocateClient.open_port_random(pid, Config.server_local_ip(), [])
      end

    v6 = AllocateClient.open_port_random(pid, Config.server_local_ip6(), [])

    relays = %{}
    extra = %{}
    errors = []

    {relays, extra, errors} =
      case v4 do
        {:ok, socket, port, token} ->
          relay = {Config.server_ip(), port}
          AllocateClient.assign_relay_socket(pid, socket, 4)
          extra = if token, do: Map.put(extra, :reservation_token, token), else: extra
          {Map.put(relays, 4, {socket, port, relay}), extra, errors}

        {:ok, socket, port} ->
          relay = {Config.server_ip(), port}
          AllocateClient.assign_relay_socket(pid, socket, 4)
          {Map.put(relays, 4, {socket, port, relay}), extra, errors}

        {:error, _} ->
          {relays, extra, [{4, 508} | errors]}
      end

    {relays, extra, errors} =
      case v6 do
        {:ok, socket, port} ->
          relay = {Config.server_ip6(), port}
          AllocateClient.assign_relay_socket(pid, socket, 8)
          {Map.put(relays, 8, {socket, port, relay}), extra, errors}

        {:error, _} ->
          {relays, extra, [{8, 440} | errors]}
      end

    cond do
      map_size(relays) == 0 ->
        fail_capacity(pid, :insufficient_capacity)

      map_size(relays) == 2 ->
        {:ok, relays, extra}

      true ->
        {fam, code} = hd(errors)
        byte = if fam == 4, do: 0x01, else: 0x02

        extra =
          Map.put(extra, :address_error_code,
            AddressFamily.address_error_code(byte, code, error_reason(code))
          )

        {:ok, relays, extra}
    end
  end

  defp family_byte(:v4), do: 4
  defp family_byte(:v6), do: 8

  defp bind_ip(:v4), do: Config.server_local_ip()
  defp bind_ip(:v6), do: Config.server_local_ip6()

  defp advertised_ip(:v4), do: Config.server_ip()
  defp advertised_ip(:v6), do: Config.server_ip6()

  defp error_reason(440), do: "Address Family not Supported"
  defp error_reason(508), do: "Insufficient Capacity"
  defp error_reason(_), do: "Error"

  defp even_port_reserve?(<<0x80>>), do: true
  defp even_port_reserve?(_), do: false

  defp apply_dont_fragment(relays, attrs, proto) do
    if Map.has_key?(attrs, :dont_fragment) and proto == @udp_proto do
      Enum.reduce_while(relays, :ok, fn {_fam, {socket, _, _}}, _ ->
        case UDP.set_dont_fragment(socket) do
          :ok -> {:cont, :ok}
          {:error, :not_supported} -> {:halt, {:error, 420, [@dont_fragment_attr]}}
        end
      end)
    else
      :ok
    end
  end

  defp respond_unknown_required(conn, types) do
    padded =
      types
      |> Enum.reduce(<<>>, fn type, acc -> acc <> <<type::16>> end)
      |> pad_unknown_attributes()

    conn = Conn.response(conn, 420, "Unknown Attribute")
    turn = conn.decoded_message

    %Conn{
      conn
      | decoded_message: %{turn | attrs: Map.put(turn.attrs, :unknown_attributes, padded)}
    }
  end

  defp pad_unknown_attributes(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      n -> bin <> :binary.copy(<<0>>, 4 - n)
    end
  end

  defp fail_capacity(pid, reason) do
    AllocateClient.destroy(pid)
    {:error, reason}
  end

  defp finish_allocate(conn, pid, attrs, lifetime, relays, extra_attrs, proto) do
    relay_addresses =
      relays
      |> Map.values()
      |> Enum.map(fn {_socket, _port, address} -> address end)

    primary_relay = hd(relay_addresses)
    primary_socket = relays |> Map.fetch!(primary_family(relays)) |> elem(0)

    AllocateClient.set_relay_addresses(pid, relays)
    AllocateClient.set_peer_details(pid, conn.decoded_message.ns, conn.decoded_message.peer_id)

    username = Map.get(attrs, :username)
    key = conn.decoded_message.key

    if is_binary(username) do
      if is_binary(key), do: AllocateClient.set_credentials(pid, username, key)
      Quota.increment(username)
    end

    if Map.has_key?(attrs, :dont_fragment) and proto == @udp_proto do
      AllocateClient.enable_dont_fragment(pid)
    end

    Store.insert(
      conn.decoded_message.transactionid,
      pid,
      primary_relay,
      Tuple5.create(conn, proto),
      primary_socket,
      nil
    )

    Xirsys.XTurn.Plugin.Lifecycle.allocation_started(%Xirsys.XTurn.Plugin.Allocation{
      id: conn.decoded_message.transactionid,
      tuple5: Xirsys.XTurn.Plugin.Table.normalise(Tuple5.to_map(Tuple5.create(conn, proto))),
      client_ip: conn.client_ip,
      client_port: conn.client_port,
      server_ip: Tuple5.turn_server_ip(conn),
      server_port: conn.server_port,
      protocol: proto,
      relay_address: primary_relay,
      transport: conn.client_socket.transport,
      ns: conn.decoded_message.ns,
      peer_id: conn.decoded_message.peer_id,
      username: username,
      started_at: DateTime.utc_now(),
      owner_pid: pid
    })

    xor_relayed =
      case relay_addresses do
        [one] -> one
        many -> many
      end

    nattrs =
      Map.merge(
        %{
          xor_mapped_address: {conn.client_ip, conn.client_port},
          xor_relayed_address: xor_relayed,
          lifetime: <<lifetime::32>>
        },
        extra_attrs
      )

    Logger.debug("Allocated")
    Conn.response(conn, :success, nattrs)
  end

  defp primary_family(relays) do
    if Map.has_key?(relays, 4), do: 4, else: relays |> Map.keys() |> List.first()
  end
end
