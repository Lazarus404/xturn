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

defmodule Xirsys.XTurn.Channels.Channel do
  @moduledoc """
  In-memory TURN channel binding for one peer on an allocation.

  ## What problem this solves

  Each ChannelBind creates state the allocation worker must refresh before
  expiry. This struct holds the channel number, owning 5-tuple, peer address,
  and the refresh timer reference.

  ## Internal

  Used inside allocation workers; not part of the public application API.

  ## RFCs

  * [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) - channel bindings and refresh (pt.11)
  """

  @typedoc "Channel number in the range 0x4000-0x7FFE, or nil before bind."
  @type channel_id :: non_neg_integer() | nil

  @typedoc "Allocation 5-tuple map used as the binding scope."
  @type tuple5 :: map() | nil

  @typedoc "Bound peer `{ip, port}`."
  @type peer_address :: {:inet.ip_address(), pos_integer()} | nil

  @typedoc "Reference for the channel refresh timer, or nil."
  @type timer_ref :: reference() | nil

  @typedoc """
  Channel binding held by an allocation worker.

  ## Fields

  * `:id` - channel number (`0x4000`-`0x7FFE`), or `nil` before bind
  * `:tuple5` - owning allocation 5-tuple map, or `nil`
  * `:peer_address` - bound peer `{ip, port}`, or `nil`
  * `:timer` - refresh timer reference, or `nil`
  """
  @type t :: %__MODULE__{
          id: channel_id(),
          tuple5: tuple5(),
          peer_address: peer_address(),
          timer: timer_ref()
        }

  @vsn "0"

  defstruct id: nil,
            tuple5: nil,
            peer_address: nil,
            timer: nil
end
