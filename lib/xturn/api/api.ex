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

defmodule Xirsys.API do
  @moduledoc """
  Maru HTTP router for XTurn operator REST endpoints.

  ## What problem this solves

  Operators need HTTP access to provision credentials, mint TURN REST shared-
  secret usernames, and inspect server state without touching the STUN/TURN
  wire protocol. This top-level router applies CORS and request body parsing,
  then mounts the auth and allocation sub-routers.

  Configure the listen port via `config :maru, Xirsys.API, http: [port: ...]`.

  ## RFCs

  - [RFC 5766](https://www.rfc-editor.org/rfc/rfc5766) (TURN service the API
    provisions credentials for)
  - [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) (long-term credentials
    created via `/auth`)
  """
  use Maru.Router

  before do
    plug(:cors)

    plug(
      Plug.Parsers,
      pass: ["*/*"],
      json_decoder: Jason,
      parsers: [:urlencoded, :json, :multipart]
    )
  end

  mount(Xirsys.API.Router.Auth)
  mount(Xirsys.API.Router.Allocation)

  rescue_from :all, as: e do
    IO.inspect(e)

    conn
    |> put_status(500)
    |> text("Server Error")
  end

  defp cors(conn, _opts) do
    conn =
      conn
      |> put_resp_header("access-control-allow-origin", "*")
      |> put_resp_header("access-control-allow-methods", "GET, POST, OPTIONS")
      |> put_resp_header("access-control-allow-headers", "content-type")

    # Maru returns 405 for OPTIONS on mounted paths (/auth, /auth/rest, ...) before
    # any route handler runs. Answer preflight here so the demo (8080 -> 8880) works.
    if conn.method == "OPTIONS" do
      conn
      |> send_resp(204, "")
      |> halt()
    else
      conn
    end
  end
end
