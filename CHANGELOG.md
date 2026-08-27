# Changelog

## 2.0.0

Public Hex release of XTurn 2 (Elixir STUN/TURN relay).

- Full TURN Allocate / Refresh / permissions / ChannelBind / ChannelData on UDP,
  TCP, TLS, and DTLS.
- STUN Binding for ICE (long-term credentials, FINGERPRINT, MESSAGE-INTEGRITY),
  optional RFC 5780 dual-IP helpers, optional RFC 3489 Binding interop.
- Coturn-compatible TURN REST shared-secret credentials (off by default).
- Optional RFC 7635 ACCESS-TOKEN path; allocation quota support.
- HTTP operator API (Maru) for minting users and REST credentials.
- Socket plane via [xsockets](https://hex.pm/packages/xsockets) `~> 1.0`.
- Media helpers via [xmedialib](https://hex.pm/packages/xmedialib); plugin
  contract via [xturn_plugin_api](https://hex.pm/packages/xturn_plugin_api)
  `~> 0.1`.
- Package docs: README, ARCHITECTURE, PLUGIN, LICENSE (HexDocs extras + module
  groups). Default config uses loopback `server_ip` and `certs/server.*` paths;
  override with `XTURN_SERVER_IP` / your cert layout for real deploys.

## 0.1.2 / 0.1.1 / 0.1.0

Earlier Hex releases (2019). See GitHub history for details.
