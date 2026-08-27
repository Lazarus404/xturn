defmodule Xirsys.XTurn.Handlers.StunTurnTest do
  use ExUnit.Case, async: false

  alias XSockets.Conn, as: SockConn
  alias XSockets.Transport.UDP
  alias Xirsys.XTurn.Conn, as: XTurnConn
  alias Xirsys.XTurn.{Handlers.StunTurn, Pipeline}
  alias XMediaLib.Stun

  defp binding_request do
    struct(Stun, %{
      class: :request,
      method: :binding,
      transactionid: 123_456_789_012
    })
  end

  test "dispatches binding request to worker pool and sends encoded success reply" do
    {:ok, client_udp} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, client_port} = :inet.port(client_udp)

    {:ok, listener} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, listener_port} = :inet.port(listener)

    sock_conn = %SockConn{
      socket: listener,
      client_ip: {127, 0, 0, 1},
      client_port: client_port,
      server_ip: {127, 0, 0, 1},
      server_port: listener_port,
      assigns: %{transport: UDP}
    }

    stun = Stun.encode(binding_request())

    assert {:ok, nil} = StunTurn.handle_packet(stun, %{}, sock_conn, nil)

    assert {:ok, {{127, 0, 0, 1}, ^listener_port, reply}} =
             :gen_udp.recv(client_udp, 0, 2_000)
    assert is_binary(reply)
    assert <<0::2, _::14, _::binary>> = reply
    assert :binary.match(reply, <<128, 40>>) != :nomatch, "STUN response should include FINGERPRINT"

    :gen_udp.close(client_udp)
    :gen_udp.close(listener)
  end

  test "process_message via pipeline returns success response attrs" do
    stun = Stun.encode(binding_request())

    xconn =
      Pipeline.process_message(%XTurnConn{
        message: stun,
        client_ip: {127, 0, 0, 2},
        client_port: 8881,
        server_ip: {127, 0, 0, 1},
        server_port: 8882
      })

    assert xconn.response.class == :success
    assert Map.get(xconn.response.attrs, :xor_mapped_address) == {{127, 0, 0, 2}, 8881}
  end
end
