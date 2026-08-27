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

defmodule Xirsys.XTurn.Auth.Client do
  @moduledoc """
  GenServer-backed ephemeral long-term TURN credential store.

  ## What problem this solves

  Operators and the HTTP API need to provision username/password pairs for
  WebRTC clients without a separate database. This process creates random or
  explicit credentials, writes them to `Auth.Table`, indexes USERHASH for
  privacy-preserving lookup, and expires rows after `@auth_lifetime` ms.

  Use `create_user/1`, `create_user/2`, or `add_user/4` from the REST API or
  application code; authentication handlers call `get_details/1` and
  `get_details_by_hash/1` during Allocate.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (long-term credentials,
    USERHASH, MESSAGE-INTEGRITY)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (TURN requires long-term
    credentials, pt.5)
  """
  use GenServer
  require Logger
  @vsn "0"

  @auth_lifetime 300_000
  @table Xirsys.XTurn.Auth.Table

  #########################################################################################################################
  # Interface functions
  #########################################################################################################################

  @doc "Starts the auth GenServer (registered name `__MODULE__`)."
  def start_link(),
    do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @doc """
  Generates a random username/password for namespace `ns` with empty `peer_id`.

  Returns `{:ok, username, password}`.
  """
  def create_user(ns),
    do: GenServer.call(__MODULE__, {:create_user, ns, ""})

  @doc """
  Generates a random username/password for `ns` and `peer_id`.

  Returns `{:ok, username, password}`.
  """
  def create_user(ns, peer_id),
    do: GenServer.call(__MODULE__, {:create_user, ns, peer_id})

  @doc """
  Stores explicit `username`/`pass` for `ns` and `peer_id`.

  Returns `{:ok, user, pass}`.
  """
  def add_user(username, pass, ns, peer_id),
    do: GenServer.call(__MODULE__, {:add_user, username, pass, ns, peer_id})

  @doc """
  Looks up credentials by username.

  Returns `{:ok, pass, ns, peer_id}` or `:error`.
  """
  def get_details(username),
    do: GenServer.call(__MODULE__, {:get_details, username})

  @doc """
  Looks up credentials by USERHASH (SHA-256 of username:realm).

  Returns `{:ok, username, pass, ns, peer_id}` or `:error`.
  """
  def get_details_by_hash(hash),
    do: GenServer.call(__MODULE__, {:get_details_by_hash, hash})

  #########################################################################################################################
  # OTP functions
  #########################################################################################################################

  @doc false
  def init([]) do
    Logger.info("Initialising auth store")
    {:ok, %{}}
  end

  @doc false
  def handle_call({:create_user, ns, peer_id}, _from, state) do
    username = Xirsys.XTurn.Auth.UUID.utc_random()
    password = Xirsys.XTurn.Auth.UUID.utc_random()
    state = put_user(state, username, {password, ns, peer_id})
    index_userhash(username)
    {:reply, {:ok, username, password}, state}
  end

  @doc false
  def handle_call({:add_user, user, pass, ns, peer_id}, _from, state) do
    state = put_user(state, user, {pass, ns, peer_id})
    index_userhash(user)
    {:reply, {:ok, user, pass}, state}
  end

  @doc false
  def handle_call({:get_details, "user"}, _from, state),
    do: {:reply, {:ok, "pass", nil, nil}, state}

  @doc false
  def handle_call({:get_details, username}, _from, state) do
    case @table.fetch(username) do
      [{^username, {pass, ns, peer_id}}] ->
        {:reply, {:ok, pass, ns, peer_id}, state}

      _ ->
        {:reply, :error, state}
    end
  end

  @doc false
  def handle_call({:get_details_by_hash, hash}, _from, state) do
    case @table.fetch(hash) do
      [{^hash, {:userhash, username}}] ->
        case @table.fetch(username) do
          [{^username, {pass, ns, peer_id}}] -> {:reply, {:ok, username, pass, ns, peer_id}, state}
          _ -> {:reply, :error, state}
        end

      _ ->
        {:reply, :error, state}
    end
  end

  @doc false
  def handle_info({:auth_expire, key}, state) do
    @table.delete(key)
    {:noreply, Map.delete(state, key)}
  end

  defp put_user(state, username, value) do
    @table.put(username, value)

    case Map.get(state, username) do
      ref when is_reference(ref) -> :timer.cancel(ref)
      _ -> :ok
    end

    ref = :timer.send_after(@auth_lifetime, self(), {:auth_expire, username})
    Map.put(state, username, ref)
  end

  defp index_userhash(username) do
    realm = Application.get_env(:xturn, :realm, "xirsys.com")

    hash =
      :crypto.hash(
        :sha256,
        XMediaLib.Stun.opaque_string(username) <> ":" <> XMediaLib.Stun.opaque_string(realm)
      )

    @table.put(hash, {:userhash, username})
  end
end
