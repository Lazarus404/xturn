###----------------------------------------------------------------------
###
### Copyright (c) 2013 - 2018 Lee Sylvester and Xirsys LLC<lee.sylvester@gmail.com>
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
###----------------------------------------------------------------------

defmodule Xirsys.Turn.Parse do
  @moduledoc """
  provides handers for TURN over STUN
  """
  # import ExProf.Macro
  require Logger
  @vsn "0"

  @stun_marker 0
  @realm Application.get_env(:xturn, :realm)
  @udp_proto <<17, 0, 0, 0>>
  @tcp_proto <<6, 0, 0, 0>>

  @allocation [:has_requested_transport, :not_allocation_exists, :authenticates, :allocate]
  @refresh [:authenticates, :refresh]
  @channelbind [:authenticates, :channelbind]
  @createpermission [:authenticates, :createperm]
  @indication [:send_indication]

  alias Xirsys.Turn.{Tuple5, Conn, Response}
  alias Xirsys.Turn.Allocate.Store
  alias Xirsys.Turn.Channels.Store, as: Channels
  alias Xirsys.Turn.Allocate.Client, as: AllocateClient
  alias Xirsys.Turn.Auth.Client, as: AuthClient
  alias Xirsys.Stun
  alias Xirsys.Utils.Socket, as: Utils

  @doc """
  Encapsulates full STUN/TURN request stub. Must be called as
  separate process
  """
  @spec process_message(Conn.t) :: Conn.t | false
  def process_message(%Conn{message: <<@stun_marker::2, _::14, _rest::binary>> = msg} = conn) do
    Logger.debug "TURN Data received"
    {:ok, turn} = Stun.decode(msg)
    do_request(%Conn{conn | decoded_message: turn}) |> Response.send()
  end

  @doc """
  Handles TURN Channel Data messages [RFC5766] section 11
  """
  def process_message(%Conn{message: <<1::2, num::14, length::16, rest::binary>>} = conn) do
    Logger.debug "TURN channeldata request (length: #{length}) from client at ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
    channeldata(<<1::2, num::14>>, length, rest, conn)
  end

  @doc """
  Handles errored TURN message extraction
  """
  def process_message(%Conn{message: <<_::binary>>}) do
    Logger.error "Error in extracting TURN message"
    false
  end

  @doc """
  ### TODO: check to make sure all attributes are handled
  ### TODO: client TCP connection establishment [RFC6062] section 4.2

  attributes include:
    binding:          Handles STUN requests [RFC5389]
    allocation:       Handles TURN allocation requests [RFC5766] section 2.2 and section 5
    refresh:          Handles TURN refresh requests [RFC5766] section 7
    channelbind:      Handles TURN channelbind requests [RFC5766] section 11
    createpermission: Handles TURN createpermission requests [RFC5766] section 9
    indication:       Handles TURN send indication requests [RFC5766] section 9
  """
  @spec do_request(Conn.t) :: Conn.t | false
  def do_request(%Conn{decoded_message: %Stun{class: :request, method: :binding}} = conn) do
    Logger.debug "STUN request from client at ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port} with ip:#{inspect conn.server_ip}, port:#{inspect conn.server_port}"
    attrs = %{
              xor_mapped_address: {conn.client_ip, conn.client_port},
              mapped_address: {conn.client_ip, conn.client_port},
              response_origin: {Utils.server_ip(), conn.server_port}
            }
    Conn.response(conn, :success, attrs)
  end
  def do_request(%Conn{decoded_message: %Stun{class: :request, method: :allocate}} = conn) do
    Logger.debug "TURN allocation request from client at ip:#{inspect conn.server_ip}, port:#{inspect conn.server_port}"
    execute(conn, @allocation)
  end
  def do_request(%Conn{decoded_message: %Stun{class: :request, method: :refresh}} = conn) do
    Logger.debug "TURN refresh request from client at ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
    execute(conn, @refresh)
  end
  def do_request(%Conn{decoded_message: %Stun{class: :request, method: :channelbind}} = conn) do
    Logger.debug "TURN channelbind request from client at ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
    execute(conn, @channelbind)
  end
  def do_request(%Conn{decoded_message: %Stun{class: :request, method: :createperm}} = conn) do
    Logger.debug "TURN createpermission request from client at ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
    execute(conn, @createpermission)
  end
  def do_request(%Conn{decoded_message: %Stun{class: :indication, method: :send}} = conn) do
    Logger.debug "TURN send indication request from client at ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
    execute(conn, @indication)
  end
  def do_request(false) do
    Logger.error "Error: STUN process halted by server"
    false
  end
  def do_request(_) do
    Logger.error "Error in processing STUN message"
    false
  end

  #########################################################################################################################
  # Action functions
  #########################################################################################################################

  @spec action(atom(), Conn.t) :: Conn.t
  defp action(_, %Conn{halt: true} = conn),
    do: conn

  # Validates the presence of the REQUESTED-TRANSPORT tag, which is
  # necessary for all TURN allocations (even if ignored)
  defp action(:has_requested_transport, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    with true <- Map.has_key?(attrs, :requested_transport),
         @udp_proto <- Map.get(attrs, :requested_transport) do
      conn
    else
      false ->
        Logger.error "Request transport not provided from ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
        Conn.response(conn, 400, "Bad Request")
      _ ->
        Logger.error "Unsupported transport protocol requested from ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
        Conn.response(conn, 442, "Unsupported Transport Protocol")
    end
  end

  # Checks if the current 5-tuple has previously been used. If so,
  # then this is a duplicate allocation request and can be safely
  # ignored.
  defp action(:not_allocation_exists, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    tup5 = [{:ca, conn.client_ip}, {:cp, conn.client_port}, {:sa, Utils.server_ip}, {:sp, conn.server_port}, {:proto, Map.get(attrs, :requested_transport)}]
    with false <- Store.exists(tup5) do
      conn
    else
      _  ->
        Logger.info "Allocation already exists from ip:#{inspect conn.client_ip}, port:#{inspect conn.client_port}"
        # Conn.response(conn, 437, "Allocation Mismatch")
        {:ok, [_client, {_ip, port}, _, _]} = Store.lookup(tup5)
        Logger.debug "#{inspect port}"
        nattrs = [
          #reservation_token: <<0::64>>,
          xor_mapped_address: {conn.client_ip, conn.client_port},
          xor_relayed_address: {Utils.server_ip(), port},
          lifetime: <<600::32>>
        ]
        Logger.debug "integrity = #{conn.decoded_message.integrity}"
        Logger.debug "Allocated"
        Conn.response(conn, :success, nattrs)
        Conn.halt(conn)
    end
  end

  # Authenticates the calling user (with the help of process_integrity).
  # Any authentication requests without integrity and user credentials
  # is at XirSys discretion (Enterprise, anyone?)
  defp action(:authenticates, %Conn{force_auth: force_auth, message: message, decoded_message: %Stun{attrs: attrs}} = conn) do
    auth = Application.get_env(:xturn, :authentication)
    with true <- Map.has_key?(attrs, :username) and (auth.required or force_auth),
         %Stun{} = turn_dec <- process_integrity(message, Map.get(attrs, :username)) do
      %Conn{conn | decoded_message: turn_dec}
    else
      _ ->
        if auth.required or force_auth,
          do: Conn.response(conn, 401, "Unauthorized"),
        else: conn
    end
  end

  # If reached, prior checks have occurred and passed. Thus, we must
  # dispatch a new process to cater for the client and his peers, whether
  # send/receive or channels.
  defp action(:allocate, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    Logger.debug "allocating #{inspect conn.decoded_message}"
    proto = Map.get(attrs, :requested_transport)
    opts = if Map.has_key?(attrs, :dont_fragment) and proto != @tcp_proto,
              do: [{:raw,0,10,<<2::native-size(32)>>}],
            else: []
    tuple5 = Tuple5.create(conn, proto)
    lifetime = 600
    {:ok, pid} = AllocateClient.create(conn.decoded_message.transactionid, conn.listener, tuple5, lifetime)
    AllocateClient.set_peer_details(pid, conn.decoded_message.ns, conn.decoded_message.peer_id)
    {:ok, socket, port} = AllocateClient.open_port_random(pid, opts)
    {:ok, permission_cache} = AllocateClient.get_permission_cache(pid)
    relay_address = {Utils.server_ip, port}
    AllocateClient.set_relay_address(pid, relay_address)
    Store.insert(conn.decoded_message.transactionid, pid, relay_address, tuple5, socket, permission_cache)
    nattrs = %{
      # reservation_token: <<0::64>>,
      xor_mapped_address: {conn.client_ip, conn.client_port},
      xor_relayed_address: {Utils.server_ip(), port},
      lifetime: <<600::32>>
    }
    Logger.debug "integrity = #{conn.decoded_message.integrity}"
    #turn2 = %Stun{conn.decoded_message | integrity: :true}
    Logger.debug "Allocated"
    Conn.response(conn, :success, nattrs)
  end

  # Updates an allocations current expiry to its maximum set lifetime value
  defp action(:refresh, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    Logger.debug "refreshing #{inspect conn.decoded_message}"
    with true <- Map.has_key?(attrs, :lifetime),
         val <- Map.get(attrs, :lifetime),
         tuple5 <-Tuple5.to_map(Tuple5.create(conn, :"_")) do
      do_refresh(conn, val, tuple5)
    else
      _ ->
        Logger.info "LIFETIME attribute not found during refresh request"
        Conn.response(conn, 400, "Bad Request")
    end
  end

  # Channel binds a peer to a given client allocation
  defp action(:channelbind, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    Logger.debug "channelbinding #{inspect conn.decoded_message}"
    with true <- Map.has_key?(attrs, :channel_number) and Map.has_key?(attrs, :xor_peer_address),
         <<channel_number::16, _::16>> <- Map.get(attrs, :channel_number),
         peer_address = {_, _} <- Map.get(attrs, :xor_peer_address),
         tuple5 <- Tuple5.to_map(Tuple5.create(conn, :"_")) do
      Logger.debug "#{Channels.exists({channel_number, tuple5})}, #{Channels.exists({peer_address, tuple5})} = #{inspect channel_number}"
      exists = Channels.exists({channel_number, tuple5})
            or Channels.exists({peer_address, tuple5})
      do_channelbind(conn, channel_number, peer_address, tuple5, exists)
    else
      _ ->
        Logger.info "Required attributes not found during channel bind"
        Conn.response(conn, 400, "Bad Request")
    end
  end

  # Assigns a permission for a peer on a given client allocation
  defp action(:createperm, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    Logger.debug "creating a permission #{inspect conn.decoded_message}"
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :"_"))
    with {_ip, _port} = p <- Map.get(attrs, :xor_peer_address),
         {:ok, [client, _peer_address, _, _]} <- Store.lookup(tuple5) do
      Logger.debug "createperm #{inspect client}, #{inspect p}"
      AllocateClient.add_permissions(client, p)
      Conn.response(conn, :success)
    else
      {:error, _} ->
        Logger.debug "client does not exist #{inspect tuple5} (createperm)"
        Conn.response(conn, 400, "Bad Request")
      _ ->
        Logger.debug "no permissions sent"
        Conn.response(conn, 400, "Bad Request")
    end
  end

  # send indication - sends data to a given peer
  defp action(:send_indication, %Conn{is_control: true}) do
    Logger.debug "cannot send indications on control connection"
    false
  end
  defp action(:send_indication, %Conn{decoded_message: %Stun{attrs: attrs}} = conn) do
    Logger.debug "send indication #{inspect conn.decoded_message}"
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :"_"))
    with true <- Map.has_key?(attrs, :data) and Map.has_key?(attrs, :xor_peer_address),
         data <- Map.get(attrs, :data),
         peer_address = {_, _} <- Map.get(attrs, :xor_peer_address),
         {:ok, [client, {_relay_ip, _relay_port}, socket, permission_cache]} <- Store.lookup(tuple5) do
      Logger.debug "sending indication to peer"
      AllocateClient.send_indication(client, peer_address, data, socket, permission_cache)
      conn
    else
      {:error, _} ->
        Logger.debug "client does not exist #{inspect tuple5} (send indication)"
        false
      _ ->
        Logger.debug "Required attributes not found during send indication"
        false
    end
  end

  #########################################################################################################################
  # Helper functions
  #########################################################################################################################

  # executes a given list of actions against a connection
  defp execute(%Conn{} = conn, actions) when is_list(actions),
    do: Enum.reduce(actions, conn, &action/2)

  # Re-processes the STUN message if integrity and username tags are present.
  # This forces TURN authentication requirements.

  ###TODO: Correctly implement custom XirSys authentication to TURN spec [RFC5766]
  defp process_integrity(msg, username) do
    Logger.info "Checking USERNAME #{inspect username}"
    with {:ok, pw, ns, peer_id} <- AuthClient.get_details(username),
         key <- username <> ":" <> @realm <> ":" <> pw,
         _ <- Logger.info("KEY = #{inspect key}"),
         {:ok, turn} <- Stun.decode(msg, key) do
      %Stun{turn | key: key, ns: ns, peer_id: peer_id}
    else
      e ->
        Logger.info "Integrity process failed: #{inspect e}"
        false
    end
  end

  # Handles incoming channel data. We route this directly to the peers, if they exist and
  # have valid channels open.
  defp channeldata(<<_channel::16>>, _length, _data, %Conn{is_control: true}) do
    Logger.debug "cannot send channel data on control connection"
    false
  end
  defp channeldata(<<channel::16>>, _length, data, %Conn{} = conn) do
    Logger.debug "channel data (#{byte_size(data)} bytes) received on channel #{inspect channel}"
    proto = :"_"
    tuple5 = Tuple5.to_map(Tuple5.create(conn, proto))
    case Channels.lookup({channel, tuple5}) do
      {:ok, [[client, _peer_address, socket, channel_cache]|_tail]} ->
        AllocateClient.send_channel(client, channel, data, socket, channel_cache)
        conn
      {:error, :not_found} ->
        Logger.debug "channel #{inspect channel} does not exist in ETS"
        false
    end
  end

  defp do_refresh(conn, <<0::32>>, tuple5) do
    case Store.lookup(tuple5) do
      {:ok, [client, {_relay_ip, _relay_port}, _, _]} ->
        Logger.debug "Refreshing with 0 time"
        AllocateClient.refresh(client, 600)
        conn
      {:error, :not_found} ->
        Conn.halt(conn)
    end
    Conn.response(conn, 437, "Allocation Mismatch")
  end
  defp do_refresh(conn, <<b::32>>, tuple5) when is_integer(b) do
    case Store.lookup(tuple5) do
      {:ok, [client, {_relay_ip, _relay_port}, _, _]} ->
        AllocateClient.refresh(client, 600)
        new_attrs = %{lifetime: <<600::32>>}
        Conn.response(conn, :success, new_attrs)
      {:error, :not_found} ->
        Conn.response(conn, 437, "Allocation Mismatch")
    end
  end
  defp do_refresh(conn, val, _) do
    Logger.info "Bad value #{inspect val} in refresh request"
    Conn.response(conn, 400, "Bad Request")
  end

  defp do_channelbind(conn, channel_number, peer_address, tuple5, false) when channel_number >= 0x4000
                                                                          and channel_number <= 0x7FFE do
    case Store.lookup(tuple5) do
      {:ok, [client, {_relay_ip, _relay_port}, _, _]} ->
        AllocateClient.add_peer_channel(client, channel_number, peer_address)
        Conn.response(conn, :success)
      {:error, :not_found} ->
        Logger.info "Invalid channel number provided in request - 5tuple not available"
        Conn.response(conn, 400, "Bad Request")
    end
  end
  defp do_channelbind(conn, channel_number, peer_address, tuple5, true) do
    {:ok, [[client, _, _]]} = Channels.lookup({channel_number, peer_address, tuple5})
    Logger.debug "refreshing timer"
    AllocateClient.refresh_channel(client, channel_number)
    Conn.response(conn, :success)
  end
  defp do_channelbind(conn, _channel_number, _peer_address, _tuple5, _) do
    Logger.info "Invalid channel number provided in request - channel number or peer address already in use"
    Conn.response(conn, 400, "Bad Request")
  end
end