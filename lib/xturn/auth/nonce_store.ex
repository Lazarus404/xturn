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

defmodule Xirsys.XTurn.Auth.NonceStore do
  @moduledoc """
  Tracks STUN/TURN nonces per client endpoint before an allocation exists.

  ## What problem this solves

  Long-term authentication (RFC 8489/5389) requires the server to issue a fresh
  NONCE on `401 Unauthorized` and verify MESSAGE-INTEGRITY on retry. Clients
  must not replay stale nonces. This GenServer stores one nonce per client
  `{ip, port}` (and supports IP-wide lookup for TCP ConnectionBind on a new
  five-tuple), expiring entries after `:nonce_max_age_ms`.

  Internal: hot-path authentication calls `issue/1`, `validate/2`, and
  `validate_for_ip/2`; operators configure expiry via application env only.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (MESSAGE-INTEGRITY,
    NONCE, PASSWORD-ALGORITHMS)
  - [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN long-term
    credential mechanism)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (TURN stale nonce,
    `438 Stale Nonce`, pt.7.2)
  """
  use GenServer

  alias Xirsys.XTurn.Auth.UUID

  @default_max_age_ms 3_600_000
  @cookie "obMatJos2"
  @cookie_flags <<0xC0, 0, 0>>

  @doc """
  Returns the PASSWORD-ALGORITHMS attribute value for RFC 8489 support.

  Advertises MD5 (1) and SHA-256 (2) with zero-length parameters.
  """
  @spec password_algorithms() :: binary()
  def password_algorithms, do: <<1::16, 0::16, 2::16, 0::16>>

  @doc "Starts the nonce store (registered as `__MODULE__`)."
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Issues a fresh nonce for `client_key` `{ip, port}` and stores it.

  Replaces any previous nonce for the same key.
  """
  @spec issue({:inet.ip_address(), pos_integer()}) :: String.t()
  def issue(client_key) do
    GenServer.call(__MODULE__, {:issue, client_key})
  end

  @doc "Returns the current nonce for `client_key`, or `nil` when none was issued."
  @spec current({:inet.ip_address(), pos_integer()}) :: String.t() | nil
  def current(client_key) do
    GenServer.call(__MODULE__, {:current, client_key})
  end

  @doc """
  Validates `nonce` against the value stored for `client_key`.

  Returns `:ok`, `:missing`, `:mismatch`, or `:stale`.
  """
  @spec validate({:inet.ip_address(), pos_integer()}, String.t() | nil) ::
          :ok | :missing | :mismatch | :stale
  def validate(_client_key, nil), do: :missing
  def validate(_client_key, ""), do: :missing

  def validate(client_key, nonce) when is_binary(nonce) do
    GenServer.call(__MODULE__, {:validate, client_key, nonce})
  end

  @doc """
  Validates `nonce` against any live nonce issued to `ip`.

  Used when ConnectionBind arrives on a new TCP five-tuple but reuses the nonce
  issued to the client IP during the initial Allocate exchange.
  """
  @spec validate_for_ip(:inet.ip_address(), String.t() | nil) ::
          :ok | :missing | :stale
  def validate_for_ip(_ip, nil), do: :missing
  def validate_for_ip(_ip, ""), do: :missing

  def validate_for_ip(ip, nonce) when is_binary(nonce) do
    GenServer.call(__MODULE__, {:validate_for_ip, ip, nonce})
  end

  @impl true
  @doc false
  def init(opts) do
    table = :ets.new(__MODULE__, [:set, :protected, read_concurrency: true])
    max_age_ms = Keyword.get_lazy(opts, :max_age_ms, &max_age_ms/0)
    interval_ref = schedule_cleanup(max_age_ms)

    {:ok, %{table: table, max_age_ms: max_age_ms, interval_ref: interval_ref}}
  end

  @impl true
  @doc false
  def handle_call({:issue, client_key}, _from, state) do
    nonce = wrap_nonce(UUID.random() |> List.to_string())
    now = System.monotonic_time(:millisecond)
    :ets.insert(state.table, {client_key, nonce, now})
    {:reply, nonce, state}
  end

  @impl true
  @doc false
  def handle_call({:current, client_key}, _from, state) do
    {:reply, lookup_nonce(state.table, client_key), state}
  end

  @impl true
  @doc false
  def handle_call({:validate, client_key, nonce}, _from, state) do
    now = System.monotonic_time(:millisecond)
    max_age_ms = max_age_ms()

    result =
      case :ets.lookup(state.table, client_key) do
        [{^client_key, stored_nonce, issued_at}] ->
          cond do
            stored_nonce != nonce -> :mismatch
            now - issued_at > max_age_ms -> :stale
            true -> :ok
          end

        [] ->
          :missing
      end

    {:reply, result, state}
  end

  @impl true
  @doc false
  def handle_call({:validate_for_ip, ip, nonce}, _from, state) do
    now = System.monotonic_time(:millisecond)
    max_age_ms = max_age_ms()

    # ConnectionBind arrives on a new TCP 5-tuple; reuse the nonce issued to
    # this client IP. O(n) ETS scan, n = live pre-allocation nonces.
    result =
      :ets.foldl(
        fn
          {{^ip, _port}, ^nonce, issued_at}, _acc ->
            cond do
              now - issued_at > max_age_ms -> :stale
              true -> :ok
            end

          _, acc ->
            acc
        end,
        :missing,
        state.table
      )

    {:reply, result, state}
  end

  @impl true
  @doc false
  def handle_info(:cleanup, state) do
    purge_stale(state.table, state.max_age_ms)
    schedule_cleanup(state.max_age_ms)
    {:noreply, state}
  end

  defp lookup_nonce(table, client_key) do
    case :ets.lookup(table, client_key) do
      [{^client_key, nonce, _issued_at}] -> nonce
      [] -> nil
    end
  end

  defp purge_stale(table, max_age_ms) do
    cutoff = System.monotonic_time(:millisecond) - max_age_ms

    :ets.select_delete(table, [
      {{:"$1", :_, :"$2"}, [{:<, :"$2", cutoff}], [true]}
    ])
  end

  defp schedule_cleanup(interval_ms) do
    Process.send_after(self(), :cleanup, interval_ms)
  end

  defp max_age_ms do
    Application.get_env(:xturn, :nonce_max_age_ms, @default_max_age_ms)
  end

  defp wrap_nonce(secret), do: @cookie <> Base.encode64(@cookie_flags) <> secret
end
