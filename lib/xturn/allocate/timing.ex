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

defmodule Xirsys.XTurn.Timing do
  @moduledoc """
  Allocation lifetime and refresh deadline helpers.

  ## What problem this solves

  TURN allocations, permissions, and channels expire unless refreshed. GenServer
  `:timeout` values must not jump when the system clock changes, so expiry uses
  monotonic deadlines. Legacy reporting still uses Gregorian seconds from
  `:calendar` where older state fields require it.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (LIFETIME and Refresh)
  """

  @doc """
  Returns the current local `{date, time}` tuple from `:calendar`.
  """
  def local_time(),
    do: :calendar.local_time()

  @doc """
  Returns the current local time as Gregorian seconds since year zero.
  """
  def now(),
    do:
      :calendar.local_time()
      |> :calendar.datetime_to_gregorian_seconds()

  @doc """
  Computes a monotonic deadline in milliseconds from a lifetime in seconds.

  ## Parameters

    * `lifetime_seconds` - allocation or permission lifetime in whole seconds

  ## Examples

      iex> deadline = Xirsys.XTurn.Timing.deadline_ms(10)
      iex> is_integer(deadline)
      true
      iex> deadline > System.monotonic_time(:millisecond)
      true
  """
  def deadline_ms(lifetime_seconds) when is_integer(lifetime_seconds) do
    System.monotonic_time(:millisecond) + lifetime_seconds * 1_000
  end

  @doc """
  Returns remaining milliseconds until expiry, or zero when already expired.

  Accepts a monotonic deadline, a map with `:deadline_ms`, a map with
  `:refresh_time` and `:lifetime`, or a `(start_time, lifetime)` pair.
  """
  def milliseconds_left(deadline_ms) when is_integer(deadline_ms) do
    now = System.monotonic_time(:millisecond)
    if deadline_ms > now, do: deadline_ms - now, else: 0
  end

  def milliseconds_left(%{deadline_ms: deadline_ms}) when is_integer(deadline_ms),
    do: milliseconds_left(deadline_ms)

  def milliseconds_left(%{refresh_time: time, lifetime: life} = _state),
    do: seconds_left(time, life) * 1_000

  @doc """
  Returns remaining milliseconds from allocation start time and lifetime (Gregorian seconds).
  """
  def milliseconds_left(start_time, lifetime),
    do: seconds_left(start_time, lifetime) * 1_000

  defp seconds_left(start_time, lifetime) do
    time_elapsed = now() - start_time

    case lifetime - time_elapsed do
      time when time <= 0 -> 0
      time -> time
    end
  end
end
