# XTurn

An Elixir **TURN / STUN** server for WebRTC.

If you have used `RTCPeerConnection` with `iceServers`, you have already talked to
something like this. When two browsers cannot send media directly (home routers,
corporate firewalls, mobile CGNAT), ICE asks a TURN server to **relay** packets.
XTurn is that relay -- plus STUN Binding for "what is my public address?"

Home: [https://github.com/Lazarus404/xturn](https://github.com/Lazarus404/xturn)

Hex: [https://hex.pm/packages/xturn](https://hex.pm/packages/xturn)

## Installation

Add to your `mix.exs` dependencies:

```elixir
def deps do
  [
    {:xturn, "~> 2.0"}
  ]
end
```

Then configure listeners and auth in your app config (see Setup below). For a
standalone server checkout, clone the repo and run `mix deps.get` then
`mix run --no-halt`.

Monorepo / local `xsockets` checkout:

```bash
mix deps.get
```

Set `XTURN_SERVER_IP` (and optional certs under `certs/`) before binding on a
real NIC. Defaults in `config/config.exs` advertise `127.0.0.1`.

## What problem this solves

WebRTC wants peer-to-peer. The internet often says no.

- **STUN** answers: "from the outside, you look like this IP:port"
- **TURN** says: "I will hold a relay address for you and forward packets to your peer"

XTurn speaks those protocols on UDP, TCP, TLS, and DTLS so browsers and native
clients can keep calls working when host / server-reflexive candidates fail.

You configure listeners and auth in Elixir config. Clients still use normal
WebRTC APIs (`iceServers: [{ urls: "turn:...", username, credential }]`).

## RFCs (the specs we implement)

You do not need to read these to run the server. They are here when you want the
official wording:

- [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) -- STUN (Binding, MESSAGE-INTEGRITY, FINGERPRINT)
- [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) -- older STUN (interop)
- [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) -- classic TURN
- [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) -- updated TURN
- [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) -- optional NAT behaviour discovery
- [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) -- TURN over TCP (ConnectionBind)
- [RFC 7635](https://www.rfc-editor.org/rfc/rfc7635) -- optional third-party ACCESS-TOKEN auth
- [RFC 3489](https://www.rfc-editor.org/rfc/rfc3489) -- optional classic STUN Binding quirks

## What you get

- UDP, TCP, TLS, and DTLS listeners
- Full TURN Allocate / Refresh / permissions / ChannelBind / ChannelData
- STUN Binding for ICE (with long-term auth, FINGERPRINT, MESSAGE-INTEGRITY)
- Optional RFC 5780 Binding helpers when you configure a second IP
- Optional RFC 3489-style UDP Binding interop (`rfc3489_compat`)
- Simple username/password store plus a small HTTP API
- Coturn-compatible TURN REST (shared-secret TTL usernames)
- Channel Binding and Data -- yes, the hot media path is real
- Fine with WebRTC data channels (the TURN relay does not care what you tunnel)

How sockets and framing work underneath lives in
[xsockets](https://hex.pm/packages/xsockets). How the TURN pieces fit
together is in [ARCHITECTURE.md](ARCHITECTURE.md). Plugin hooks:
[PLUGIN.md](PLUGIN.md).

## Setup

Open `config/config.exs`. Almost everything lives there (and in `config/runtime.exs`
for env overrides).

### Logging

Debug logging is great while you learn. It is expensive at scale.

For production, set the logger to `:info` or `:error`. Leave `:debug` for local
dev only.

```elixir
config :logger,
  level: :debug,
  compile_time_purge_level: :debug
```

### Ports

Default idea (when cert files exist):

- **3478** -- plain STUN/TURN (UDP + TCP, IPv4 + IPv6)
- **5349** -- secure TURNS (TLS/DTLS)

Port **443** is never hardcoded. To serve TURNS on 80 or 443, set
`XTURN_TURNS_PORT` at runtime.

```elixir
config :xturn,
  authentication: %{required: true},
  permissions: %{required: false},
  realm: "xirsys.com",
  listen: [
    {:udp, ~c"0.0.0.0", 3478},
    {:tcp, ~c"0.0.0.0", 3478},
    {:udp, ~c"::", 3478},
    {:tcp, ~c"::", 3478},
    {:udp, ~c"0.0.0.0", 5349, :secure},
    {:tcp, ~c"0.0.0.0", 5349, :secure},
    {:udp, ~c"::", 5349, :secure},
    {:tcp, ~c"::", 5349, :secure}
  ],
  server_ip: {127, 0, 0, 1},
  server_local_ip: {0, 0, 0, 0},
  certs: [
    certfile: "certs/server.crt",
    keyfile: "certs/server.key"
  ]
```

Env knobs:

- `XTURN_STUN_PORT` (default `3478`) -- plain port
- `XTURN_TURNS_PORT` (default `5349`) -- secure port
- `XTURN_SERVER_IP` / `XTURN_SERVER_IP6` -- extra listen addresses at runtime

See `config/runtime.exs` and `Xirsys.XTurn.ListenConfig`.

Config cheat sheet:

- **`authentication.required: true`** -- reject clients without a valid user/password
- **`permissions.required: false`** -- TURN normally needs CreatePermission; set
  false only if you knowingly want a looser lab
- **`server_ip`** -- the public IP clients should see in candidates
- **`server_local_ip`** -- the NIC you bind sockets to (you still set each listener)

### Authentication (think "how ICE logs in")

Browsers and coturn-style stacks use two common patterns. XTurn supports both.

**Long-term credentials** -- a username/password you store (via `POST /auth` or
`Auth.Client.add_user/4`). On first try the server answers `401` with a nonce;
the client retries with `MESSAGE-INTEGRITY` using
`MD5(username:realm:password)` as the key. Nonces rotate and expire after
`nonce_max_age_ms` (default one hour). An expired nonce becomes `438 Stale Nonce`.

**Shared-secret / TTL credentials (TURN REST)** -- same idea as coturn
`use-auth-secret`. **Off by default.** Turn it on and mint credentials with
`GET /auth/rest?username=<id>&ttl=<seconds>` (returns **503** while disabled):

```elixir
config :xturn,
  shared_secret: [
    enabled: true,
    secret: "your-shared-secret",
    default_ttl_seconds: 86_400
  ]
```

Usernames look like `"<expiry-unix>:<user-id>"`. Passwords are
`Base64(HMAC-SHA1(secret, username))`. If a username matches that timestamp
shape and shared secret is enabled, we verify that way; otherwise we use the
long-term store.

**Allocation quota** -- optional `allocation_quota` caps how many allocations
one username can hold at once (RFC 8656 -> **486**). Unset by default so a
laptop lab is not capped.

**RFC 7635 third-party auth** -- optional ACCESS-TOKEN path. Long-term + SHA-256
STUN integrity stays the default.

**Short-term credentials** -- not implemented for TURN (and RFC 8656 says TURN
should use long-term). Plain STUN Binding can skip auth in our pipeline. Coturn
does not do short-term TURN either.

### TURNS certificates (for real browsers)

Production `turns:` / DTLS needs a publicly trusted cert for the hostname clients
dial (for example `turn.example.com`):

```elixir
config :xturn,
  certs: [
    certfile: "/etc/xturn/certs/turn.example.com.crt",
    keyfile: "/etc/xturn/certs/turn.example.com.key"
  ],
  cert_watch_interval_ms: 60_000
```

Issue and renew certs **outside** XTurn with [lego](https://github.com/go-acme/lego)
and DNS-01. XTurn polls the PEM paths and reloads secure listeners when files
change.

#### Obtain and renew (lego + DNS-01)

Start with Let's Encrypt. Switching CA later is mostly a `--server` flag change;
XTurn does not care which CA signed the files.

```bash
lego --email ops@example.com \
     --domains turn.example.com \
     --dns cloudflare \
     --path /etc/xturn/lego \
     renew --days 30 \
     --renew-hook 'XTURN_CERT_DOMAIN=turn.example.com /path/to/xturn/scripts/xturn-deploy-certs.sh'
```

Copy [`scripts/xturn-deploy-certs.sh`](scripts/xturn-deploy-certs.sh) onto the host
and set `XTURN_CERT_DOMAIN` in the hook. The script installs PEMs under
`/etc/xturn/certs/` (mode `0640`). No special signal is required; the cert
watcher notices within one poll interval.

For an immediate reload, set `XTURN_SERVICE` to your systemd unit name so the
hook can send `SIGHUP` (XTurn maps that to `Certs.reload/0`).

Check the chain looks complete:

```bash
openssl crl2pkcs7 -nocrl -certfile /etc/xturn/certs/turn.example.com.crt \
  | openssl pkcs7 -print_certs -noout
```

Expect two or more certificates listed.

#### Native clients

Browsers use the OS trust store. Some native WebRTC stacks (Flutter, React Native,
Unreal) ship a stricter root list and have rejected some Let's Encrypt chains in
the past. If you ship native apps, test `turns:` early; ZeroSSL or Google Trust
Services are common fallbacks if you see "Unknown CA".

#### Local development

Self-signed files under `certs/` are enough (see `config/test.exs`). No lego
required.

## HTTP API (Maru)

[Maru](https://github.com/elixir-maru/maru) is a small Elixir HTTP layer. XTurn
uses it for operator endpoints: create users, mint TURN REST credentials, peek
at allocation counts.

```elixir
config :maru, Xirsys.API,
  http: [port: 8880]
```

Change the port if something else already owns 8880.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contact

Questions or ideas: Jahred at experts@xirsys.com

## License

BSD-3-Clause. See [LICENSE.md](LICENSE.md).
