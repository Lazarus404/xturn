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

defmodule Xirsys.XTurn do
  @moduledoc """
  XTurn is a STUN/TURN relay server for real-time media (WebRTC, VoIP, and similar).

  ## What problem this solves

  Many devices sit behind NAT or firewalls and cannot receive inbound UDP/TCP
  directly. Interactive Connectivity Establishment (ICE) lets two peers find
  working paths; when direct paths fail, a TURN relay forwards media through a
  server the client can reach. STUN discovers reflexive addresses and tests NAT
  behavior; TURN allocates relay ports, permissions, and channels so peers can
  exchange packets via the server.

  XTurn implements the server side: it listens for STUN/TURN, authenticates
  clients, opens relay sockets, and forwards media on a fast path separate from
  control requests. STUN message encoding and decoding use
  [xmedialib](https://github.com/Lazarus404/xmedialib) (`XMediaLib.Stun`).

  ## Main modules

  - `Xirsys.XTurn` -- OTP application entry; starts stores and `RootSupervisor`
  - `Xirsys.XTurn.RootSupervisor` / `Supervisor` -- listener and worker tree
  - `Xirsys.XTurn.Pipeline` -- control-plane STUN/TURN request dispatch
  - `Xirsys.XTurn.DataPlane` -- relay media fast path (ChannelData, Send)
  - `Xirsys.XTurn.Conn` / `Response` -- per-request context for action chains
  - `Xirsys.XTurn.Binding` -- STUN Binding (address discovery)
  - `Xirsys.XTurn.Allocate.Client` / `Store` -- per-allocation GenServer and index
  - `Xirsys.XTurn.ClientWorker.Pool` -- sharded control workers
  - `Xirsys.XTurn.ListenConfig` / `ListenRegistry` -- bind ports and RFC 5780 sockets
  - `Xirsys.XTurn.DualIp` -- dual-homed NAT behavior discovery helpers

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (TURN extensions: address families, even-port)
  - [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) (NAT behavior discovery: CHANGE-REQUEST, OTHER-ADDRESS)
  - [RFC 6062](https://www.rfc-editor.org/rfc/rfc6062) (TURN over TCP / TCP relay)
  - [RFC 7635](https://www.rfc-editor.org/rfc/rfc7635) (TURN REST API; optional access tokens)
  - [RFC 3489](https://www.rfc-editor.org/rfc/rfc3489) (classic STUN interop when `:rfc3489_compat` is enabled)
  """
  use Application

  @doc """
  OTP application callback.

  Initialises ETS stores (allocations, channels, permissions, auth, quota, plugins),
  ensures `ListenRegistry`, rewrites `:listen` ports via `ListenConfig`, and
  starts `RootSupervisor` with the resolved listener list.
  """
  def start(_type, _args) do
    Xirsys.XTurn.Allocate.Store.init()
    Xirsys.XTurn.Channels.Store.init()
    Xirsys.XTurn.Permissions.Store.init()
    Xirsys.XTurn.Auth.Table.init()
    Xirsys.XTurn.Allocate.Bytes.init()
    Xirsys.XTurn.Allocate.Quota.init()
    Xirsys.XTurn.Plugin.Table.init()
    Xirsys.XTurn.ReservationStore.init()
    :ok = Xirsys.XTurn.ListenRegistry.ensure!()

    listen =
      Application.get_env(:xturn, :listen, [])
      |> Xirsys.XTurn.ListenConfig.rewrite_ports()

    Application.put_env(:xturn, :listen, listen)
    Xirsys.XTurn.RootSupervisor.start_link(listen)
  end
end
