defmodule StunTest do

  use ExUnit.Case # bring in the test functionality
  require Logger

  alias Xirsys.Stun
  alias Xirsys.Turn.{Conn, Parse}

  @conn %Conn{
    client_ip: {127,0,0,2},
    client_port: 8881,
    server_ip: {127,0,0,3},
    server_port: 8882
  }
  @stun %Stun{
    class: :request,
    method: :binding,
    transactionid: 123456789012
  }

  setup do
    {:ok, stun: Stun.encode(@stun)}
  end

  test "valid stun packet format", %{stun: stun} do
    # is at least 16 bits and starts with 00 bits
    assert valid_stun(stun)
  end

  test "returns valid response", %{stun: stun} do
    conn = Parse.process_message(%Conn{@conn | message: stun})
    assert conn.response.class == :success,
      "STUN request should be valid"
    assert :proplists.get_value(:"XOR-MAPPED-ADDRESS", conn.response.attrs || []) == {@conn.client_ip, @conn.client_port},
      "must return a xor-mapped-address"
    assert :proplists.get_value(:"MAPPED-ADDRESS", conn.response.attrs || []) == {@conn.client_ip, @conn.client_port},
      "must return a mapped-address"
    assert :proplists.get_value(:"RESPONSE-ORIGIN", conn.response.attrs || []) == {@conn.server_ip, @conn.server_port},
      "must return a response-origin"
  end

  defp valid_stun(<<0::2, _::14, _rest::binary>>) do
    true
  end
  defp valid_stun(_) do
    false
  end
end