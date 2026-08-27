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

defmodule Xirsys.XTurn.SocketPipeline do
  @moduledoc """
  Socket pipeline for stream transports (TCP, TLS-over-TCP).

  ## What problem this solves

  TCP delivers a byte stream, not discrete datagrams. This pipeline wires the
  STUN/TURN accumulator (with required ChannelData padding) to the handler
  that routes control and media for each complete frame.

  ## Internal

  Started by `xsockets` for TCP/TLS listeners; not part of the public
  application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - ChannelData padding on stream transports (pt.11.5)
  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - STUN over TCP framing
  """
  use XSockets.Pipeline

  alias Xirsys.XTurn.Accumulators.StunTurn
  alias Xirsys.XTurn.Handlers.StunTurn, as: StunTurnHandler

  tier :root,
    accumulator: {StunTurn, framing: :stream},
    handler: StunTurnHandler
end

defmodule Xirsys.XTurn.SocketPipeline.Datagram do
  @moduledoc """
  Socket pipeline for datagram transports (UDP, DTLS).

  ## What problem this solves

  UDP datagrams already bound message boundaries. This pipeline uses the
  STUN/TURN accumulator in datagram mode so unpadded ChannelData from browsers
  is accepted, then hands complete frames to the shared handler.

  ## Internal

  Started by `xsockets` for UDP/DTLS listeners; not part of the public
  application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - optional ChannelData padding on UDP (pt.11.5)
  * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) - STUN over UDP
  """
  use XSockets.Pipeline

  alias Xirsys.XTurn.Accumulators.StunTurn
  alias Xirsys.XTurn.Handlers.StunTurn, as: StunTurnHandler

  tier :root,
    accumulator: {StunTurn, framing: :datagram},
    handler: StunTurnHandler
end
