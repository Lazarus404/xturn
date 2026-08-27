defmodule StunTurnDataPlaneTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias XSockets.Conn, as: SockConn
  alias Xirsys.XTurn.ClientWorker.Pool
  alias Xirsys.XTurn.Handlers.StunTurn

  test "ChannelData and Send are not enqueued on ClientWorker" do
    send_frame =
      Stun.encode(%Stun{
        class: :indication,
        method: :send,
        transactionid: System.unique_integer([:positive]),
        fingerprint: false,
        attrs: %{
          xor_peer_address: {{10, 0, 0, 1}, 4242},
          data: "send-#{System.unique_integer([:positive])}"
        }
      })

    channel_payload = "chan#{System.unique_integer([:positive])}"
    channel_frame = <<0x4001::16, byte_size(channel_payload)::16, channel_payload::binary>>

    control_frame =
      Stun.encode(%Stun{
        class: :request,
        method: :binding,
        transactionid: System.unique_integer([:positive]),
        fingerprint: false,
        attrs: %{}
      })

    sock_conn = %SockConn{
      client_ip: {127, 0, 0, 1},
      client_port: 12_345,
      server_ip: {127, 0, 0, 1},
      server_port: 3478,
      socket: :fake,
      assigns: %{transport: XSockets.Transport.UDP}
    }

    workers = pool_workers()
    Enum.each(workers, &:sys.suspend/1)

    try do
      assert {:ok, nil} = StunTurn.handle_packet(send_frame, %{}, sock_conn, nil)
      refute enqueued?(workers, send_frame)

      assert {:ok, nil} = StunTurn.handle_packet(channel_frame, %{}, sock_conn, nil)
      refute enqueued?(workers, channel_frame)

      assert {:ok, nil} = StunTurn.handle_packet(control_frame, %{}, sock_conn, nil)
      assert enqueued?(workers, control_frame)
    after
      Enum.each(workers, &:sys.resume/1)
    end
  end

  defp pool_workers do
    for i <- 0..(Pool.pool_size() - 1) do
      pid = Process.whereis(Pool.worker_name(i))
      assert is_pid(pid)
      pid
    end
  end

  defp enqueued?(workers, frame) do
    Enum.any?(workers, fn pid ->
      {:messages, messages} = Process.info(pid, :messages)

      Enum.any?(messages, fn
        {:"$gen_cast", {:process, ^frame, _}} -> true
        {:process, ^frame, _} -> true
        _ -> false
      end)
    end)
  end
end
