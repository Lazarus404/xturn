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

defmodule Xirsys.XTurn.Certs do
  @moduledoc """
  Certificate reload for TURNS and DTLS listeners.

  ## What problem this solves

  WebRTC clients require valid TLS certificates for `turns:` and DTLS. Issuance
  and renewal happen out of process (for example lego with DNS-01). This module
  clears the OTP PEM cache and restarts secure listeners when operators or
  automation install new files at the configured `:certs` paths.

  Called by `Certs.Watcher` (polling) and `Certs.SignalHandler` (SIGHUP).

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN over TLS)
  - [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) (TURN over DTLS)
  """
  require Logger

  @spec paths() :: [Path.t()]
  @doc """
  Returns configured certificate file paths (cert, key, optional CA bundle).

  Omits `nil` entries from `:certs` application env.
  """
  def paths do
    certs = Application.get_env(:xturn, :certs, [])

    Enum.filter([certs[:certfile], certs[:keyfile], certs[:cacertfile]], & &1)
  end

  @spec reload() :: :ok
  @doc """
  Clears the PEM cache and restarts secure (TLS/DTLS) listeners with fresh certs.
  """
  def reload do
    Logger.info("XTurn: reloading TLS certificates")
    :ssl.clear_pem_cache()
    Xirsys.XTurn.Supervisor.restart_secure_listeners()
  end
end
