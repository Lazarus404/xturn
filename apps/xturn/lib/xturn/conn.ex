###----------------------------------------------------------------------
###
### Copyright (c) 2013 - 2018 Lee Sylvester and Xirsys LLC<lee.sylvester@gmail.com>
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
###----------------------------------------------------------------------

defmodule Xirsys.Turn.Conn do
  @moduledoc """
  TURN connection object
  """
  require Logger

  alias Xirsys.Turn.Conn
  alias Xirsys.Turn.Response

  @vsn "0"
  defstruct listener: nil,
            message: nil,
            decoded_message: nil,
            client_ip: nil,
            client_port: nil,
            server_ip: nil,
            server_port: nil,
            is_control: false,
            force_auth: false,
            response: nil,
            halt: nil

  def halt(%Conn{} = conn),
    do: %Conn{conn | halt: true}

  def response(conn, class, attrs \\ nil)
  def response(%Conn{} = conn, class, attrs) when is_atom(class),
    do: %Conn{conn | response: %Response{class: class, attrs: attrs}}
  def response(%Conn{} = conn, err, msg) when is_integer(err),
    do: %Conn{conn | response: %Response{err_no: err, message: msg}} |> Conn.halt
end