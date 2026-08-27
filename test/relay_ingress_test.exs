defmodule RelayIngressTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Allocate.{Client, Store}
  alias Xirsys.XTurn.Permissions.Store, as: Permissions
  alias Xirsys.XTurn.{ClientSocket, Tuple5}

  test "peer UDP is delivered by ingress, not Allocate.Client" do
    tuple5 = %Tuple5{
      client_address: {127, 0, 0, 1},
      client_port: 40_001,
      server_address: {127, 0, 0, 1},
      server_port: 3478,
      protocol: :udp
    }

    client_socket = ClientSocket.new(XSockets.Transport.UDP, self(), {127, 0, 0, 1}, 40_001)
    tid = "ingress-#{System.unique_integer([:positive])}"
    {:ok, alloc} = Client.start_link(tid, client_socket, tuple5, 600)

    on_exit(fn ->
      if Process.alive?(alloc), do: GenServer.stop(alloc, :normal)
      Permissions.revoke_all(Tuple5.to_map(tuple5))
    end)

    {:ok, socket, port} = Client.open_port_random(alloc, {127, 0, 0, 1})
    assert :ok = Client.assign_relay_socket(alloc, socket, 4)
    relay = {{127, 0, 0, 1}, port}

    assert :ok =
             Client.set_relay_addresses(alloc, %{4 => {socket, port, relay}})

    Store.insert(tid, alloc, relay, tuple5, socket, nil)
    Permissions.grant(Tuple5.to_map(tuple5), {127, 0, 0, 1})

    payload = "peer-#{System.unique_integer([:positive])}"
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, payload)
    :gen_udp.close(peer)

    assert_receive {:turn_client, bin}, 1_000
    assert {:ok, decoded} = XMediaLib.Stun.decode(bin, nil)
    assert decoded.attrs.data == payload

    {:messages, messages} = Process.info(alloc, :messages)

    refute Enum.any?(messages, fn
             {:udp, _, _, _, ^payload} -> true
             _ -> false
           end)
  end
end
