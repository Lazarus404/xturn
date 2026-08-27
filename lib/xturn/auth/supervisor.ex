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

defmodule Xirsys.XTurn.Auth.Supervisor do
  @moduledoc """
  OTP supervisor for TURN authentication services.

  ## What problem this solves

  Nonce tracking and credential storage run in dedicated processes that must
  restart independently without taking down the relay. This supervisor boots
  `Auth.NonceStore` and `Auth.Client` under a `:one_for_one` tree.

  Internal: started from the application supervision tree, not configured
  directly by operators.

  ## RFCs

  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (long-term credentials,
    NONCE, MESSAGE-INTEGRITY)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (TURN authentication
    requirements, stale nonce handling)
  """
  use Supervisor
  require Logger

  @doc "Starts the auth supervisor."
  def start_link(_opts \\ []) do
    Supervisor.start_link(__MODULE__, :ok)
  end

  @doc false
  def init(:ok) do
    Logger.info("starting auth client")

    children = [
      %{id: Xirsys.XTurn.Auth.NonceStore, start: {Xirsys.XTurn.Auth.NonceStore, :start_link, []}},
      %{id: Xirsys.XTurn.Auth.Client, start: {Xirsys.XTurn.Auth.Client, :start_link, []}}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
