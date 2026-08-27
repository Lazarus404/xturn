# xturn plugins

Data-plane plugins sit on the relay path: after a frame is classified, before it is sent to a peer or back to a client. They are per-allocation, optional, and **off the hot path when none are configured**.

The contract lives in [xturn-plugin-api](https://github.com/Lazarus404/xturn-plugin-api)
(`Xirsys.XTurn.Plugin`). xturn implements the runtime. Example plugins live in
[xturn-plugins](https://github.com/Lazarus404/xturn-plugins).

## What a plugin can see

Relayed WebRTC media is **DTLS-SRTP ciphertext**. xturn does not terminate the browser-to-browser handshake. A plugin sees opaque bytes (plus TURN framing metadata), not decoded audio/video.

| Goal | At a relay hook? |
|---|---|
| Metering, loss/reorder stats, opaque capture | Yes |
| Drop / throttle / allowlist by first bytes | Yes (do not rewrite SRTP headers - that breaks the auth tag) |
| Transcode, STT, SFU by SSRC | No - needs an ICE endpoint, not a relay |

xturn's own TLS/DTLS on `:secure` listeners is an **outer** hop. It is already stripped before plugins run.

## Active vs passive

| | `:active` | `:passive` |
|---|---|---|
| Runs in | The calling process (`DataPlane` or `RelayIngress.Worker`) | Its own supervised `Plugin.Instance` |
| Can transform or drop | Yes - must be fast | No (copy only) |
| State | Immutable value from `init/2`. Mutable state must be the plugin's own ETS/process - `handle_frame/3` is concurrent | Threaded through `handle_frame/3` in the instance |
| Typical use | Policy, guard, drop | Recording, metrics, export |

`hooks/0` is `[:egress]`, `[:ingress]`, or both.

- **Egress** - client -> peer (`ChannelData` or Send indication)
- **Ingress** - peer -> client (`ChannelData` or Data indication), including hairpin

## Runtime modules

```
config :xturn, plugins: [{Mod, opts}, ...]
        |
Plugin.Manager          <- load/validate, :persistent_term enabled flag, monitors
        |
Lifecycle.allocation_started/1   after Allocate.Store.insert
        |
  attach?/2 -> init/2
        |
  active: entry on Chain
  passive: InstanceSupervisor starts Plugin.Instance
        |
Plugin.Table            <- ETS, read_concurrency, key = normalised 5-tuple
        |
Dispatch.egress/5  /  Dispatch.ingress/4
```

| Module | Role |
|---|---|
| `Plugin.Manager` | Reads `:plugins`, validates callbacks, `watch/3` monitors, `reload/0` |
| `Plugin.Lifecycle` | Attach at allocate, detach on owner `:DOWN` or `Allocate.Client.terminate/2` |
| `Plugin.Table` | 5-tuple -> `%Chain{}`. `normalise/1` forces protocol to `:_` so ingress and egress hit the same row |
| `Plugin.Chain` | Four lists: egress/ingress x active/passive |
| `Plugin.Dispatch` | Run active chain; `send/2` copies to passive pids |
| `Plugin.Instance` | Passive GenServer; `{:frame, payload, frame}`; optional `handle_info/2` |
| `Plugin.InstanceSupervisor` | `DynamicSupervisor`, restart `:temporary` |
| `Plugin.Supervisor` | Manager + instance supervisor |

Hook sites (nothing else needed):

1. `DataPlane` - egress on ChannelData and Send; ingress on hairpin
2. `RelayIngress.Worker` - ingress on peer UDP
3. `Actions.Allocate` - `allocation_started/1` after `Store.insert`
4. `Allocate.Client.terminate/2` and Manager owner-monitor - `allocation_ended/2`

## Zero cost when unused

1. `:persistent_term.get({Xirsys.XTurn.Plugin, :enabled}, false)` - `false` if the plugin list is empty. Dispatch returns `{:ok, payload}` immediately.
2. One `ets.lookup` on `Plugin.Table` when enabled. No row -> pass through.

Do not put plugin columns on `Allocate.Store` or `Channels.Store` - those tables have different keys.

## Configure

```elixir
# mix.exs
{:xturn_plugins, "~> 0.1"}

# config/config.exs
config :xturn,
  plugins: [
    {Xirsys.XTurn.Plugin.Guard, mode: :monitor, payload_types: [96, 111]},
    {Xirsys.XTurn.Plugin.Metrics, flush_ms: 5_000}
  ]
```

Each entry is `{module, keyword}`. `enabled: false` on an entry skips that module at load. `Plugin.Manager.reload/0` re-reads env (does not re-attach existing allocations).

### Framework options (stripped before `init/2`)

| Key | Default | Meaning |
|---|---|---|
| `:enabled` | `true` | Skip this module at load |
| `:fail` | `:open` | Active: `:closed` drops the frame on exception/`{:error, _}` |
| `:budget_us` | `500` | Active: sampled mean latency above this **disables** the module process-wide |
| `:sample_every` | `256` | How often to time `handle_frame/3` |
| `:max_inflight` | `500` | Passive: drop copies when the instance mailbox is this deep |

Plugin-specific keys (`:mode`, `:payload_types`, `:flush_ms`, ...) are passed through to `attach?/2` and `init/2`.

## Write a plugin

Depend on `xturn_plugin_api` only (not on `xturn`) so the package tests standalone.

```elixir
defmodule MyApp.Meter do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :passive

  @impl true
  def hooks, do: [:egress, :ingress]

  @impl true
  def attach?(%Xirsys.XTurn.Plugin.Allocation{}, _opts), do: true

  @impl true
  def init(_allocation, opts) do
    Process.send_after(self(), :flush, Keyword.get(opts, :flush_ms, 5_000))
    {:ok, %{bytes: 0, packets: 0, flush_ms: Keyword.get(opts, :flush_ms, 5_000)}}
  end

  @impl true
  def handle_frame(payload, %Xirsys.XTurn.Plugin.Frame{}, state) do
    {:ok, %{state | bytes: state.bytes + byte_size(payload), packets: state.packets + 1}}
  end

  @impl true
  def handle_info(:flush, state) do
    :telemetry.execute([:my_app, :meter, :flush], %{bytes: state.bytes, packets: state.packets}, %{})
    Process.send_after(self(), :flush, state.flush_ms)
    {:ok, %{state | bytes: 0, packets: 0}}
  end

  @impl true
  def handle_close(_reason, state) do
    :telemetry.execute([:my_app, :meter, :close], %{bytes: state.bytes, packets: state.packets}, %{})
    :ok
  end
end
```

Active drop-only (do not rewrite SRTP):

```elixir
defmodule MyApp.AllowStunStun do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :active

  @impl true
  def hooks, do: [:egress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, _opts), do: {:ok, nil}

  @impl true
  def handle_frame(<<0::2, _::bitstring>> = payload, _frame, _state), do: {:ok, payload}
  def handle_frame(_payload, _frame, _state), do: :drop
end
```

`attach?/2` returning `false`, or `init/2` returning `:ignore`, skips that allocation. Filter on `%Allocation{}` fields (`username`, `client_ip`, `relay_address`, ...).

### Callbacks

Required: `mode/0`, `hooks/0`, `attach?/2`, `init/2`, `handle_frame/3`.

Optional: `handle_close/2` (passive teardown; reason is the allocation exit, not supervisor `:shutdown`), `handle_info/2` (passive; `self()` is the instance - use `Process.send_after/3` for periodic work).

`handle_frame/3` returns:

- Active: `{:ok, binary}` | `:drop` | `{:error, term}`
- Passive: `{:ok, new_state}`

`%Frame{}`: `direction`, `framing` (`:send_indication` | `:channel_data` | `:data_indication`), `peer_ip`, `peer_port`, `channel_number` (egress ChannelData only), `size`, `at` (monotonic us).

## Dispatch rules

- Active plugins run **in list order**. A `:drop` stops the chain; later actives and all passives are skipped.
- After all actives succeed, each matching passive gets `{:frame, payload, frame}` if inflight <= `max_inflight`. Overflow emits `[:xturn, :plugin, :passive, :dropped]` and skips that copy.
- Active exception or `{:error, _}`: `:fail :open` (default) continues with the original payload; `:fail :closed` drops.
- If sampled mean latency exceeds `:budget_us`, the module is disabled in `:persistent_term` for the whole node until restart/reload.

## Telemetry

| Event | When |
|---|---|
| `[:xturn, :plugin, :attached]` | Instance added to a chain |
| `[:xturn, :plugin, :detached]` | Passive instance stopped |
| `[:xturn, :plugin, :active, :stop]` | Sampled `handle_frame` duration |
| `[:xturn, :plugin, :active, :dropped]` | Active returned `:drop` or fail-closed |
| `[:xturn, :plugin, :active, :exception]` | Rescue/catch in active |
| `[:xturn, :plugin, :active, :disabled]` | Over budget |
| `[:xturn, :plugin, :passive, :dispatched]` | Copy sent |
| `[:xturn, :plugin, :passive, :dropped]` | Inflight cap |

## Examples in-tree

- `Xirsys.XTurn.Plugin.Guard` (`xturn-plugins`) - RFC 7983 first-byte + RTP PT allowlist; `:monitor` vs `:enforce`
- `Xirsys.XTurn.Plugin.Metrics` - per-allocation counters / jitter
- `xturn/test/support/plugins/` - passthrough, dropper, transformer, closer (used by `test/plugin/`)

```bash
cd xturn && mix test test/plugin/dispatch_test.exs test/plugin/integration_test.exs
```
