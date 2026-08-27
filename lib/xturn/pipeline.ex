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

defmodule Xirsys.XTurn.Pipeline do
  @moduledoc """
  Decodes and dispatches STUN/TURN control requests.

  ## What problem this solves

  TURN servers handle many message types: Binding, Allocate, Refresh, permission
  and channel management, TCP relay setup, and more. Each type has prerequisite
  checks (authentication, existing allocation, transport). The pipeline decodes
  wire bytes via [xmedialib](https://github.com/Lazarus404/xmedialib), picks the
  handler from method and class, and runs an ordered action list on `%Conn{}`.

  Relayed media (ChannelData and Send indications) normally bypasses this module
  on the listener fast path; workers invoke it only for control-plane frames.

  ## Internal note

  Called from `ClientWorker`; operators do not call `process_message/1` directly.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN decode and Binding)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (Allocate, Refresh, ChannelBind, permissions, ChannelData)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (address family and extension attributes)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (Connect, ConnectionBind)
  - [RFC 7635](https://www.rfc-editor.org/rfc/rfc7635) (ACCESS-TOKEN when enabled)
  - [RFC 3489](https://www.rfc-editor.org/rfc/rfc3489) (classic decode fallback on UDP when configured)
  """
  # import ExProf.Macro
  require Logger
  @vsn "0"

  @stun_marker 0
  # @udp_proto <<17, 0, 0, 0>>
  # @tcp_proto <<6, 0, 0, 0>>

  alias Xirsys.XTurn.Conn

  alias Xirsys.XTurn.Actions.{
    Allocate,
    Authenticates,
    ChannelBind,
    ChannelData,
    Connect,
    ConnectionBind,
    CreatePerm,
    HasRequestedTransport,
    NotAllocationExists,
    Refresh,
    SendIndication
  }

  alias Xirsys.XTurn.Allocate.{Client, Store}
  alias Xirsys.XTurn.Binding
  alias Xirsys.XTurn.Tuple5
  alias XMediaLib.Stun
  alias XSockets.Transport.UDP

  @allocation [HasRequestedTransport, NotAllocationExists, Authenticates, Allocate]
  @refresh [Authenticates, Refresh]
  @channelbind [Authenticates, ChannelBind]
  @createpermission [Authenticates, CreatePerm]
  @connect [Authenticates, Connect]
  @connection_bind [Authenticates, ConnectionBind]
  @indication [SendIndication]
  @channeldata [ChannelData]

  @doc """
  Entry point for a single client message.

  Decodes STUN/TURN (with optional RFC 3489 fallback on UDP when configured),
  handles RFC 5766 ChannelData, rejects malformed non-STUN frames, and delegates
  to `do_request/1`. Returns an updated `%Conn{}` or `false` on decode failure.
  """
  @spec process_message(%Conn{}) :: %Conn{} | false
  def process_message(%Conn{message: msg} = conn) do
    case msg do
      <<@stun_marker::2, _::14, _rest::binary>> ->
        Logger.debug("TURN Data received")

        case decode_message(msg, conn) do
          {:ok, %{unknown_required: [_ | _] = unknown, class: :request} = turn} ->
            unknown_attribute(%Conn{conn | decoded_message: turn}, unknown)

          {:ok, %{unknown_required: [_ | _]} = turn} ->
            %Conn{conn | decoded_message: turn}

          {:ok, turn} ->
            do_request(%Conn{conn | decoded_message: turn})

          {:error, _} ->
            false
        end

      <<1::2, _num::14, length::16, _rest::binary>> ->
        Logger.debug(
          "TURN channeldata request (length: #{length}) from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(maybe_mark_tcp_control(conn), @channeldata)

      <<_::binary>> ->
        Logger.error("Error in extracting TURN message")
        false
    end
  end

  @doc """
  Routes a decoded STUN/TURN message to the appropriate handler.

  Dispatches by `decoded_message.method` and `class`:

    * `:binding` - `Binding.process/1`
    * `:allocate`, `:refresh`, `:channelbind`, `:createperm`, `:connect`, `:connection_bind` - action chains
    * `:send` indication - `SendIndication` (blocked on TCP control allocations)
    * `:channel` data - `ChannelData` action chain

  Returns the updated `%Conn{}` or `false`.
  """
  @spec do_request(%Conn{} | false) :: %Conn{} | false
  def do_request(input) do
    case input do
      %Conn{decoded_message: %{class: :request, method: :binding}} = conn ->
        Logger.debug(
          "STUN request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          } with ip:#{inspect(conn.server_ip)}, port:#{inspect(conn.server_port)}"
        )

        Binding.process(conn)

      %Conn{decoded_message: %{class: :request, method: :allocate, attrs: attrs}} = conn
      when is_map(attrs) ->
        if Map.has_key?(attrs, :access_token) and not Xirsys.XTurn.Auth.AccessToken.enabled?() do
          unknown_attribute(conn, [0x001B])
        else
          do_allocate_request(conn)
        end

      %Conn{decoded_message: %{class: :request, method: :allocate}} = conn ->
        do_allocate_request(conn)

      %Conn{decoded_message: %{class: :request, method: :refresh}} = conn ->
        Logger.debug(
          "TURN refresh request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(conn, @refresh)

      %Conn{decoded_message: %{class: :request, method: :channelbind}} = conn ->
        Logger.debug(
          "TURN channelbind request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(conn, @channelbind)

      %Conn{decoded_message: %{class: :request, method: :createperm}} = conn ->
        Logger.debug(
          "TURN createpermission request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(conn, @createpermission)

      %Conn{decoded_message: %{class: :request, method: :connect}} = conn ->
        Logger.debug(
          "TURN connect request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(conn, @connect)

      %Conn{decoded_message: %{class: :request, method: :connection_bind}} = conn ->
        Logger.debug(
          "TURN connection_bind request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(conn, @connection_bind)

      %Conn{decoded_message: %{class: :indication, method: :send}} = conn ->
        Logger.debug(
          "TURN send indication request from client at ip:#{inspect(conn.client_ip)}, port:#{
            inspect(conn.client_port)
          }"
        )

        execute(maybe_mark_tcp_control(conn), @indication)

      %Conn{decoded_message: %{class: :indication, method: :binding}} = conn ->
        conn

      %Conn{decoded_message: %{class: :request, method: method}} = conn when not is_atom(method) ->
        conn

      %Conn{decoded_message: %{class: class}} = conn when class in [:success, :error] ->
        conn

      false ->
        Logger.error("Error: STUN process halted by server")
        false

      %Conn{} = conn ->
        conn

      _ ->
        Logger.error("Error in processing STUN message")
        false
    end
  end

  defp do_allocate_request(conn) do
    Logger.debug(
      "TURN allocation request from client at ip:#{inspect(conn.client_ip)}, port:#{
        inspect(conn.client_port)
      }"
    )

    execute(conn, @allocation)
  end

  # executes a given list of actions against a connection
  defp execute(%Conn{} = conn, actions) when is_list(actions),
    do: Enum.reduce(actions, conn, &process/2)

  defp process(_, %Conn{halt: true} = conn), do: conn

  defp process(action, conn), do: apply(action, :process, [conn])

  defp unknown_attribute(conn, types) do
    padded =
      types
      |> Enum.reduce(<<>>, fn type, acc -> acc <> <<type::16>> end)
      |> pad_unknown_attributes()

    conn = Conn.response(conn, 420, "Unknown Attribute")
    turn = conn.decoded_message
    %Conn{conn | decoded_message: %{turn | attrs: Map.put(turn.attrs, :unknown_attributes, padded)}}
  end

  defp pad_unknown_attributes(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      n -> bin <> :binary.copy(<<0>>, 4 - n)
    end
  end

  defp decode_message(msg, conn) do
    case Stun.decode(msg) do
      {:ok, turn} ->
        {:ok, turn}

      {:error, :malformed} ->
        if rfc3489_compat?(conn), do: Stun.decode_classic(msg), else: {:error, :malformed}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp rfc3489_compat?(conn) do
    Application.get_env(:xturn, :rfc3489_compat) == true and
      match?(%{transport: UDP}, conn.client_socket)
  end

  defp maybe_mark_tcp_control(%Conn{} = conn) do
    tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))

    case Store.lookup(tuple5) do
      {:ok, [client, _relay, _socket, _perms]} ->
        if Client.requested_transport(client) == :tcp do
          %Conn{conn | is_control: true}
        else
          conn
        end

      _ ->
        conn
    end
  end
end
