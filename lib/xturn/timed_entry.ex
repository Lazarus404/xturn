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

defmodule Xirsys.XTurn.TimedEntry do
  @moduledoc """
  Map of values with per-key expiry timers.

  ## What problem this solves

  TURN permissions and channel bindings expire unless refreshed. Each allocation
  tracks many peers and channels, each with its own lifetime. This module wraps
  a map with `Process.send_after/3` so inserting or replacing a key cancels the
  old timer and schedules a new expiry message to the owning process.

  ## Internal note

  Used inside allocation GenServers; not configured by operators.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (permission and channel lifetimes)
  """

  @doc """
  Inserts `value` under `key`, scheduling `expire_msg` to `owner` after `lifetime_ms`.

  Any existing entry for `key` is removed (and its timer cancelled) first.

  ## Parameters

    * `map` - timed-entry map
    * `key` - map key (typically peer IP or channel number)
    * `value` - stored payload
    * `lifetime_ms` - milliseconds until expiry message is sent
    * `owner` - process that receives `expire_msg`
    * `expire_msg` - message sent when the timer fires
  """
  def put(map, key, value, lifetime_ms, owner, expire_msg) do
    map
    |> remove(key)
    |> then(fn map ->
      ref = Process.send_after(owner, expire_msg, lifetime_ms)
      Map.put(map, key, {ref, value})
    end)
  end

  @doc """
  Returns whether `key` exists in the timed-entry map.
  """
  def has_key?(map, key), do: Map.has_key?(map, key)

  @doc """
  Fetches the value stored under `key`, ignoring the timer reference.
  """
  def fetch(map, key) do
    case Map.get(map, key) do
      {_, value} -> {:ok, value}
      _ -> :error
    end
  end

  @doc """
  Removes `key` from the map, cancelling its timer when present.

  ## Parameters

    * `map` - timed-entry map
    * `key` - map key
  """
  def remove(map, key) do
    case Map.get(map, key) do
      {ref, _} when is_reference(ref) -> Process.cancel_timer(ref)
      _ -> :ok
    end

    Map.delete(map, key)
  end

  @doc """
  Returns all keys in the timed-entry map.

  ## Parameters

    * `map` - timed-entry map

  ## Examples

      iex> ref = make_ref()
      iex> map = %{"a" => {ref, 1}, "b" => {ref, 2}}
      iex> Xirsys.XTurn.TimedEntry.keys(map)
      ["a", "b"]
  """
  def keys(map), do: Map.keys(map)

  @doc """
  Cancels every timer in the map and returns an empty map.

  ## Parameters

    * `map` - timed-entry map
  """
  def cancel_all(map) do
    Enum.each(map, fn
      {_key, {ref, _}} when is_reference(ref) -> Process.cancel_timer(ref)
      _ -> :ok
    end)

    %{}
  end
end
