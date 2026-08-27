defmodule Xirsys.XTurn.Integration.ListenerTest do
  use ExUnit.Case, async: false

  alias XSockets.{DatagramServer, SockSupervisor, TierSupervisor, Transport.UDP}
  alias XMediaLib.Stun

  @test_ip {127, 0, 0, 1}

  setup do
    start_supervisors()
    :ok
  end

  test "UDP listener responds to STUN binding" do
    {:ok, listener} =
      DatagramServer.start_link(
        transport: UDP,
        ip: @test_ip,
        port: 0,
        pipeline: Xirsys.XTurn.SocketPipeline.Datagram,
        assigns: %{transport: UDP}
      )

    port = DatagramServer.port(listener)

    stun =
      Stun.encode(%Stun{
        class: :request,
        method: :binding,
        transactionid: 99_001,
        fingerprint: false
      })

    {:ok, sender} = :gen_udp.open(0, [:binary, active: false, reuseaddr: true])

    try do
      :ok = :gen_udp.send(sender, @test_ip, port, stun)
      assert_receive_udp_reply(sender)
    after
      :gen_udp.close(sender)

      try do
        GenServer.stop(listener)
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp assert_receive_udp_reply(sender, attempts \\ 50)

  defp assert_receive_udp_reply(_sender, 0),
    do: flunk("expected STUN reply, got {:error, :timeout}")

  defp assert_receive_udp_reply(sender, attempts) do
    case :gen_udp.recv(sender, 4096, 100) do
      {:ok, {{127, 0, 0, 1}, _port, reply}} ->
        assert <<0::2, _::14, _::binary>> = reply

      {:error, :timeout} ->
        assert_receive_udp_reply(sender, attempts - 1)

      other ->
        flunk("expected STUN reply, got #{inspect(other)}")
    end
  end

  defp start_supervisors do
    for start <- [
          {SockSupervisor, :start_link, [[]]},
          {TierSupervisor.Task, :start_link, [[]]},
          {TierSupervisor.Pool, :start_link, [[]]}
        ] do
      case apply(elem(start, 0), elem(start, 1), elem(start, 2)) do
        {:ok, _} -> :ok
        {:error, {:already_started, _}} -> :ok
      end
    end
  end
end
