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

defmodule Xirsys.XTurn.Allocate.Quota do
  @moduledoc """
  Per-username concurrent allocation limit.

  ## What problem this solves

  Service operators often cap how many live relay allocations one username may
  hold. This ETS-backed counter enforces `:allocation_quota` from application
  env, returning STUN error 486 when the limit is reached.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (allocation error 486 Allocation Quota Reached)
  """

  @table :xturn_alloc_quota

  @doc "Creates the public allocation-quota ETS table if it does not exist."
  @spec init() :: :ok
  def init do
    ensure_table()
    :ok
  end

  @doc """
  Returns `:ok` or `{:error, 486}` when the username is at the configured quota.
  """
  def check(username) when is_binary(username) do
    case Application.get_env(:xturn, :allocation_quota) do
      limit when is_integer(limit) ->
        ensure_table()

        if count(username) >= limit do
          {:error, 486}
        else
          :ok
        end

      _ ->
        :ok
    end
  end

  @doc "Increments the live allocation count for `username`. Returns `:ok`."
  def increment(username) when is_binary(username) do
    ensure_table()
    _ = :ets.update_counter(@table, username, {2, 1}, {username, 0})
    :ok
  end

  @doc "Decrements the live allocation count for `username`. Returns `:ok`."
  def decrement(username) when is_binary(username) do
    ensure_table()

    try do
      case :ets.update_counter(@table, username, {2, -1, 0, 0}) do
        0 -> :ets.delete(@table, username)
        _ -> :ok
      end
    rescue
      ArgumentError -> :ok
    end
  end

  defp count(username) do
    case :ets.lookup(@table, username) do
      [{^username, n}] -> n
      _ -> 0
    end
  end

  # Race-safe: concurrent ClientWorkers can all see `:undefined` then race `:ets.new/2`.
  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        try do
          :ets.new(@table, [:named_table, :public, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end

      _ ->
        :ok
    end
  end
end
