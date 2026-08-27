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

defmodule Xirsys.XTurn.Conn do
  @moduledoc """
  Mutable request context passed through STUN/TURN action pipelines.

  ## What problem this solves

  Each incoming STUN or TURN message needs shared state: the raw bytes, decoded
  attributes, who sent it, which server socket received it, and any response
  built so far. Action modules (authenticate, allocate, channel bind, and so on)
  read and update one `%Conn{}` instead of threading many arguments.

  ## Internal note

  Library and server internals only; operators configure XTurn via application
  env and REST API, not by building `%Conn{}` structs directly.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN message format)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN methods and errors)
  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (`reply_from` / `reply_to` for CHANGE-REQUEST)
  """
  alias Xirsys.XTurn.{Auth.NonceStore, Conn, Response}
  alias XMediaLib.Stun

  @software "xirsys-turnserver"

  @typedoc """
  STUN/TURN request context.

  ## Fields

  * `:message` - raw inbound bytes, or `nil`
  * `:decoded_message` - decoded `%XMediaLib.Stun{}` (or map-like attrs), or unset
  * `:client_socket` - `%ClientSocket{}` used to reply, or `nil`
  * `:client_ip` / `:client_port` - peer that sent the request
  * `:server_ip` / `:server_port` - local listen endpoint that received it
  * `:is_control` - when `true`, data-plane Send/ChannelData paths are blocked
  * `:force_auth` - require MESSAGE-INTEGRITY even when auth is optional
  * `:response` - `%Response{}` being built, or `nil`
  * `:halt` - when `true`, later pipeline actions are skipped
  * `:splice_peer` - optional TCP splice peer port
  * `:reply_from` - optional `{transport_mod, socket}` override for the reply
  * `:reply_to` - optional `{ip, port}` override for where to send the reply
  """
  @type t :: %__MODULE__{
          message: binary() | nil,
          decoded_message: term(),
          client_socket: Xirsys.XTurn.ClientSocket.t() | nil,
          client_ip: :inet.ip_address() | nil,
          client_port: pos_integer() | nil,
          server_ip: :inet.ip_address() | nil,
          server_port: pos_integer() | nil,
          is_control: boolean(),
          force_auth: boolean(),
          response: Response.t() | nil,
          halt: boolean() | nil,
          splice_peer: port() | nil,
          reply_from: {module(), term()} | nil,
          reply_to: {:inet.ip_address(), :inet.port_number()} | nil
        }
  defstruct message: nil,
            decoded_message: nil,
            client_socket: nil,
            client_ip: nil,
            client_port: nil,
            server_ip: nil,
            server_port: nil,
            is_control: false,
            force_auth: false,
            response: nil,
            halt: nil,
            splice_peer: nil,
            reply_from: nil,
            reply_to: nil


  @doc "Stops further actions from running on this connection."
  def halt(%Conn{} = conn), do: %Conn{conn | halt: true}

  @doc """
  Attaches a success or error response to the connection.

  * `response(conn, class, attrs)` - success response (`class` is an atom, e.g. `:success`)
  * `response(conn, err, msg)` - error response (integer code + reason phrase)
  * `response(conn, err, msg, nonce)` - error with explicit nonce (401/438)
  """
  @spec response(t(), atom() | integer(), map() | binary() | any()) :: t()
  def response(conn, class, attrs \\ nil)

  def response(%Conn{} = conn, class, attrs) when is_atom(class),
    do: %Conn{conn | response: %Response{class: class, attrs: attrs}}

  def response(%Conn{} = conn, err, msg) when is_integer(err) do
    conn
    |> build_response(err, msg, error_nonce(conn))
    |> then(fn %Conn{} = built ->
      %Conn{built | response: %Response{err_no: err, message: msg}}
    end)
    |> halt()
  end

  @doc """
  Builds an error response with an explicit `nonce` (401/438).
  """
  @spec response(t(), integer(), binary(), String.t()) :: t()
  def response(%Conn{} = conn, err, msg, nonce) when is_integer(err) and is_binary(nonce) do
    conn
    |> build_response(err, msg, nonce)
    |> then(fn %Conn{} = built ->
      %Conn{built | response: %Response{err_no: err, message: msg}}
    end)
    |> halt()
  end

  @doc """
  Encodes `conn.response` into STUN wire format.

  Returns `{:ok, iodata()}` when a reply should be sent, or `:noreply` when
  the pipeline produced no response (e.g. indications, halts without response).
  """
  @spec to_reply(t()) :: {:ok, iodata()} | :noreply
  def to_reply(%Conn{} = conn) do
    case conn do
      %Conn{response: %Response{err_no: err}, decoded_message: %{class: :error}} = c
      when is_integer(err) ->
        encode_reply(c)

      %Conn{response: %Response{err_no: err, message: msg}} = c when is_integer(err) ->
        c
        |> build_response(err, msg, error_nonce(c))
        |> encode_reply()

      %Conn{response: %Response{class: cls, attrs: attrs}} = c when is_atom(cls) ->
        c
        |> build_response(cls, attrs)
        |> encode_reply()

      %Conn{} ->
        :noreply
    end
  end

  defp build_response(%Conn{decoded_message: %{classic: true} = turn} = conn, class, attrs)
       when is_atom(class) do
    new_attrs =
      cond do
        is_map(attrs) -> Map.put(attrs, :software, @software)
        true -> %{software: @software}
      end

    new_turn =
      struct(turn, %{
        class: class,
        fingerprint: false,
        attrs: new_attrs
      })

    %Conn{conn | decoded_message: new_turn}
  end

  defp build_response(%Conn{decoded_message: turn} = conn, class, attrs) when is_atom(class) do
    new_attrs =
      cond do
        is_map(attrs) -> Map.put(attrs, :software, @software)
        true -> %{software: @software}
      end

    new_turn =
      struct(turn, %{
        class: class,
        fingerprint: true,
        attrs: new_attrs
      })

    %Conn{conn | decoded_message: new_turn}
  end

  defp build_response(%Conn{decoded_message: turn} = conn, 300, err_msg, _nonce) do
    new_attrs =
      %{
        error_code: {300, err_msg},
        software: @software
      }
      |> maybe_put_alternate_server()
      |> maybe_put_alternate_domain()

    new_turn =
      struct(turn, %{
        class: :error,
        fingerprint: true,
        integrity: false,
        key: nil,
        attrs: new_attrs
      })

    %Conn{conn | decoded_message: new_turn}
  end

  defp build_response(%Conn{decoded_message: turn} = conn, 400, err_msg, _nonce) do
    new_attrs = %{
      error_code: {400, err_msg},
      software: @software
    }

    new_turn = struct(turn, %{class: :error, fingerprint: true, attrs: new_attrs})
    %Conn{conn | decoded_message: new_turn}
  end

  defp build_response(%Conn{decoded_message: turn} = conn, 420, err_msg, _nonce) do
    new_attrs = %{
      error_code: {420, err_msg},
      software: @software
    }

    new_turn = struct(turn, %{class: :error, fingerprint: true, attrs: new_attrs})
    %Conn{conn | decoded_message: new_turn}
  end

  defp build_response(%Conn{decoded_message: turn} = conn, err_no, err_msg, nonce)
       when err_no in [401, 438] do
    new_attrs =
      %{
        error_code: {err_no, err_msg},
        nonce: nonce,
        realm: realm(),
        password_algorithms: NonceStore.password_algorithms(),
        software: @software
      }
      |> maybe_put_third_party_auth()

    new_turn = struct(turn, %{class: :error, fingerprint: true, attrs: new_attrs})
    %Conn{conn | decoded_message: new_turn}
  end

  defp build_response(%Conn{decoded_message: turn} = conn, err_no, err_msg, nonce)
       when is_integer(err_no) do
    new_attrs = %{
      error_code: {err_no, err_msg},
      nonce: nonce,
      realm: realm(),
      software: @software
    }

    new_turn = struct(turn, %{class: :error, fingerprint: true, attrs: new_attrs})
    %Conn{conn | decoded_message: new_turn}
  end

  defp encode_reply(%Conn{decoded_message: turn}) when is_map(turn) do
    {:ok, Stun.encode(turn)}
  end

  defp encode_reply(_conn), do: :noreply

  defp error_nonce(%Conn{client_ip: ip, client_port: port})
       when not is_nil(ip) and not is_nil(port) do
    client_key = {ip, port}

    case NonceStore.current(client_key) do
      nil -> NonceStore.issue(client_key)
      nonce -> nonce
    end
  end

  defp error_nonce(_conn), do: NonceStore.issue({{127, 0, 0, 1}, 0})

  defp realm(), do: Application.get_env(:xturn, :realm, "xirsys.com")

  defp maybe_put_alternate_server(attrs) do
    case Application.get_env(:xturn, :alternate_server) do
      {ip, port} when is_tuple(ip) and is_integer(port) ->
        Map.put(attrs, :alternate_server, {ip, port})

      _ ->
        attrs
    end
  end

  defp maybe_put_alternate_domain(attrs) do
    case Application.get_env(:xturn, :alternate_domain) do
      domain when is_binary(domain) and domain != "" ->
        Map.put(attrs, :alternate_domain, domain)

      _ ->
        attrs
    end
  end

  defp maybe_put_third_party_auth(attrs) do
    case Xirsys.XTurn.Auth.AccessToken.enabled?() && Xirsys.XTurn.Auth.AccessToken.as_uri() do
      uri when is_binary(uri) and uri != "" ->
        Map.put(attrs, :third_party_authorization, uri)

      _ ->
        attrs
    end
  end
end
