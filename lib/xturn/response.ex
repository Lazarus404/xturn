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

defmodule Xirsys.XTurn.Response do
  @moduledoc """
  Pending STUN success or error attached to `%Conn{}` during pipeline processing.

  ## What problem this solves

  Action modules decide *what* to answer (success attributes or an error code) but
  should not encode wire format themselves. They set `%Response{}` on the conn;
  `Conn.to_reply/1` adds SOFTWARE, fingerprint, realm, and nonce, then encodes via
  [xmedialib](https://github.com/Lazarus404/xmedialib).

  ## Internal note

  Not used by operators; created only inside server action handlers.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) / [RFC 5389](https://www.rfc-editor.org/rfc/rfc5389) (STUN responses)
  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN error codes)
  """

  @typedoc """
  Pending STUN response before wire encoding.

  ## Fields

  - `:class` - success class atom (e.g. `:success`) when building a success reply
  - `:attrs` - attribute map for success responses
  - `:err_no` - numeric STUN error code (e.g. `401`, `437`, `486`)
  - `:message` - UTF-8 reason phrase for error responses
  """
  @type t :: %__MODULE__{
          class: atom() | nil,
          attrs: map() | nil,
          err_no: integer() | nil,
          message: binary() | nil
        }
  defstruct class: nil,
            attrs: nil,
            err_no: nil,
            message: nil

end
