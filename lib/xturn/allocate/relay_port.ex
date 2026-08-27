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

defmodule Xirsys.XTurn.RelayPort do
  @moduledoc """
  Opens relay UDP ports according to server port policy.

  ## What problem this solves

  Each TURN allocation needs one or more UDP ports on the server to relay
  traffic. Clients may request random ports, a preferred port, a range, or RFC
  8656 even-port allocation with an optional reserved adjacent port. This module
  implements those bind policies on top of the socket transport layer.

  ## Internal note

  Called from `Allocate.Client` during Allocate success handling.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (relay transport address)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (EVEN-PORT, RESERVATION-TOKEN)
  """
  require Logger

  alias XSockets.Transport.UDP
  alias Xirsys.XTurn.ReservationStore

  @even_attempts 20

  @doc """
  Opens a relay UDP socket on `server_ip` using `policy`.

  `policy` may be `:random`, `{:preferred, port}`, or `{:range, min, max}`.
  Returns `{:ok, socket}` or `{:error, reason}`.
  """
  @spec open(:inet.ip_address(), term(), keyword()) :: {:ok, port()} | {:error, term()}
  def open(server_ip, policy, opts \\ []) do
    open_free_udp_port(policy, server_ip, opts)
  end

  @doc """
  Opens an even relay UDP port, optionally reserving the next odd port.

  When `reserve_next?` is true, returns an 8-byte token for the reserved
  adjacent port. Returns `{:ok, socket, port, token}` or `{:error, reason}`.
  """
  @spec open_even(:inet.ip_address(), boolean(), keyword()) ::
          {:ok, port(), non_neg_integer(), binary() | nil} | {:error, term()}
  def open_even(server_ip, reserve_next?, opts \\ []) do
    with {:ok, socket, port} <- open_even_port(server_ip, opts, @even_attempts),
         {:ok, token} <- maybe_reserve_next(reserve_next?, socket, port, server_ip, opts) do
      {:ok, socket, port, token}
    end
  end

  defp open_even_port(_server_ip, _opts, 0), do: {:error, :eaddrinuse}

  defp open_even_port(server_ip, opts, attempts) do
    case UDP.open_relay(server_ip, opts) do
      {:ok, socket} ->
        {:ok, port} = :inet.port(socket)

        if rem(port, 2) == 0 do
          {:ok, socket, port}
        else
          :gen_udp.close(socket)
          open_even_port(server_ip, opts, attempts - 1)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_reserve_next(false, _socket, _port, _server_ip, _opts), do: {:ok, nil}

  defp maybe_reserve_next(true, socket, port, server_ip, opts) do
    case UDP.open_relay(server_ip, Keyword.put(opts, :port, port + 1)) do
      {:ok, next_socket} ->
        token = :crypto.strong_rand_bytes(8)
        :ok = ReservationStore.reserve(token, next_socket, port + 1)
        {:ok, token}

      {:error, reason} ->
        :gen_udp.close(socket)
        {:error, reason}
    end
  end

  defp open_free_udp_port(:random, server_ip, opts) do
    case UDP.open_relay(server_ip, opts) do
      {:ok, socket} -> {:ok, socket}
      {:error, reason} -> {:error, reason}
    end
  end

  defp open_free_udp_port({:range, min_port, max_port}, server_ip, opts) when min_port <= max_port do
    case UDP.open_relay(server_ip, Keyword.merge(opts, port: min_port)) do
      {:ok, socket} ->
        {:ok, socket}

      {:error, :eaddrinuse} ->
        open_free_udp_port({:range, min_port + 1, max_port}, server_ip, opts)

      {:error, reason} ->
        Logger.error("UDP open #{inspect(server_ip)} -> #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp open_free_udp_port({:range, _min_port, _max_port}, server_ip, opts) do
    reason = "Port range exhausted"
    Logger.error("UDP open #{inspect(server_ip)} -> #{inspect(reason)}")
    open_free_udp_port(:random, server_ip, opts)
  end

  defp open_free_udp_port({:preferred, port}, server_ip, opts) do
    case UDP.open_relay(server_ip, Keyword.merge(opts, port: port)) do
      {:ok, socket} ->
        {:ok, socket}

      {:error, :eaddrinuse} ->
        open_free_udp_port(:random, server_ip, opts)

      {:error, reason} ->
        Logger.error("UDP open #{inspect(server_ip)} -> #{inspect(reason)}")
        {:error, reason}
    end
  end
end
