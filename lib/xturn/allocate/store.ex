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

defmodule Xirsys.XTurn.Allocate.Store do
  @moduledoc """
  ETS index of active TURN allocations and relay ingress rows.

  ## What problem this solves

  Control handlers, the data plane, and relay ingress must find the allocation
  process, client socket, and channel map quickly from a transaction id, client
  five-tuple, or inbound relay `{ip, port}`. This store holds those mappings
  and publishes relay socket rows for peer-to-client forwarding.

  ## Internal note

  Initialised at application start; rows are inserted/deleted by `Allocate.Client`.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (allocation identity and relay address)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TCP allocation flag in tuple5 index)
  """
  # import Exts

  @vsn "0"

  alias Xirsys.XTurn.Tuple5, as: T5

  @doc "Creates the public allocation ETS table."
  def init(),
    do: Exts.new(__MODULE__, access: :public)

  @doc """
  Inserts a new allocation under `tid` and indexes it by normalized `tuple5`.

  Returns `:ok`.
  """
  def insert(tid, pid, {_ip, _port} = relay, %T5{} = tuple5, socket, perms) do
    normalized = normalize_tuple5(tuple5)
    tcp? = tcp_proto?(tuple5.protocol)
    Exts.write(__MODULE__, {tid, {pid, relay, normalized, socket, perms}})
    :ets.insert(__MODULE__, {{:tuple5, normalized}, {:t5, pid, relay, socket, perms, tcp?}})
    :ok
  end

  @doc false
  def lookup_tuple5(tuple5) when is_list(tuple5) do
    case tuple5_record(tuple5) do
      {pid, relay, socket, perms, _tcp?} -> {:ok, pid, relay, socket, perms}
      :error -> {:error, :not_found}
    end
  end

  @doc false
  def tcp_allocation?(tuple5) when is_list(tuple5) do
    match?({_, _, _, _, true}, tuple5_record(tuple5))
  end

  @doc """
  Looks up an allocation by one of:

    * transaction id (`tid`) - `{:ok, pid, socket, perms}`
    * normalized five-tuple list - `{:ok, [pid, relay, socket, perms]}`
    * relay `{ip, port}` - `{:ok, [pid, tuple5, socket, perms]}`

  Returns `{:error, :not_found}` when no match exists.
  """
  def lookup(tid) when is_binary(tid) do
    case Exts.read(__MODULE__, tid) do
      [{_tid, {pid, _, _, socket, perms}}] -> {:ok, pid, socket, perms}
      [] -> {:error, :not_found}
    end
  end

  def lookup([{:ca, _}, {:cp, _}, {:sa, _}, {:sp, _}, {:proto, _}] = tuple5),
    do: match({:_, {:"$1", :"$2", normalize_tuple5_list(tuple5), :"$3", :"$4"}})

  def lookup({ip, _port} = relay_address) when is_tuple(ip),
    do: match({:_, {:"$1", relay_address, :"$2", :"$3", :"$4"}})

  @doc "Returns `true` when `lookup/1` would succeed for `criteria`."
  def exists(criteria) do
    case lookup(criteria) do
      {:ok, _} -> true
      _ -> false
    end
  end

  @doc """
  Deletes an allocation or raw ETS row.

  When `key` is a transaction id, unpublishes relay rows and removes the
  `{:tuple5, _}` secondary index. Any other key is deleted directly.
  """
  def delete(key) do
    if is_binary(key), do: delete_tid(key), else: :ets.delete(__MODULE__, key)
  end

  defp delete_tid(tid) do
    case Exts.read(__MODULE__, tid) do
      [{_tid, {pid, _relay, tuple5, _socket, _perms}}] when is_list(tuple5) ->
        :ets.delete(__MODULE__, {:tuple5, normalize_tuple5_list(tuple5)})
        unpublish_relay(pid)

      [{_tid, {pid, _relay, _tuple5, _socket, _perms}}] ->
        unpublish_relay(pid)

      _ ->
        :ok
    end

    :ets.delete(__MODULE__, tid)
  end

  @doc false
  def publish_relays(pid, client_socket, peer_to_channel, %T5{} = tuple5, relays)
      when is_pid(pid) and is_map(relays) do
    normalized = normalize_tuple5_list(T5.to_map(tuple5))

    for {_fam, %{socket: socket, address: address}} <- relays,
        is_tuple(address) do
      record = {pid, client_socket, peer_to_channel, normalized, address}
      :ets.insert(__MODULE__, {{:relay, address}, record})
      :ets.insert(__MODULE__, {{:sock, socket}, record})
      handoff_socket(socket, address)
    end

    :ok
  end

  @doc false
  def update_peer_to_channel(pid, peer_to_channel) when is_pid(pid) and is_map(peer_to_channel) do
    :ets.foldl(
      fn
        {{tag, key}, rec}, _acc
        when tag in [:relay, :sock] and elem(rec, 0) == pid ->
          client_socket = elem(rec, 1)
          tuple5 = elem(rec, 3)
          address = if tuple_size(rec) == 5, do: elem(rec, 4)
          :ets.insert(
            __MODULE__,
            {{tag, key}, {pid, client_socket, peer_to_channel, tuple5, address}}
          )
          :ok

        _, _ ->
          :ok
      end,
      :ok,
      __MODULE__
    )
  end

  @doc false
  def unpublish_relay(pid) when is_pid(pid) do
    :ets.foldl(
      fn
        {{tag, key}, rec}, _acc
        when tag in [:relay, :sock] and elem(rec, 0) == pid ->
          :ets.delete(__MODULE__, {tag, key})
          :ok

        _, _ ->
          :ok
      end,
      :ok,
      __MODULE__
    )
  end

  @doc false
  def lookup_relay({ip, _port} = relay_address) when is_tuple(ip) do
    case :ets.lookup(__MODULE__, {:relay, relay_address}) do
      [{{:relay, _}, record}] -> {:ok, decode_relay(record)}
      [] -> :error
    end
  end

  @doc false
  def lookup_sock(socket) when is_port(socket) do
    case :ets.lookup(__MODULE__, {:sock, socket}) do
      [{{:sock, _}, record}] -> {:ok, decode_relay(record)}
      [] -> :error
    end
  end

  defp decode_relay({pid, client_socket, peer_to_channel, tuple5, address}) do
    %{
      pid: pid,
      client_socket: client_socket,
      peer_to_channel: peer_to_channel,
      tuple5: tuple5,
      address: address
    }
  end

  defp decode_relay({pid, client_socket, peer_to_channel, tuple5}) do
    decode_relay({pid, client_socket, peer_to_channel, tuple5, nil})
  end

  defp handoff_socket(socket, {_ip, port}) do
    case Xirsys.XTurn.RelayIngress.assign_socket(socket, port) do
      :ok -> :ok
      {:error, _} -> :ok
    end
  end

  defp match(criteria) do
    lookup = Exts.match(__MODULE__, criteria)
    maybe_values(lookup)
  end

  defp maybe_values(%{values: [client]}) when is_list(client),
    do: {:ok, client}

  defp maybe_values(_),
    do: {:error, :not_found}

  defp tuple5_record(tuple5) do
    key = normalize_tuple5_list(tuple5)

    case :ets.lookup(__MODULE__, {:tuple5, key}) do
      [{{:tuple5, _}, {:t5, pid, relay, socket, perms, tcp?}}] ->
        {pid, relay, socket, perms, tcp?}

      [] ->
        case lookup(tuple5) do
          {:ok, [pid, relay, socket, perms]} -> {pid, relay, socket, perms, false}
          {:error, :not_found} -> :error
        end
    end
  end

  defp tcp_proto?(<<6, 0, 0, 0>>), do: true
  defp tcp_proto?(:tcp), do: true
  defp tcp_proto?(_), do: false

  defp normalize_tuple5(%T5{} = tuple5), do: normalize_tuple5_list(T5.to_map(tuple5))

  defp normalize_tuple5_list(tuple5) do
    map = Map.new(tuple5)

    [
      {:ca, map[:ca]},
      {:cp, map[:cp]},
      {:sa, map[:sa]},
      {:sp, map[:sp]},
      {:proto, :_}
    ]
  end
end
