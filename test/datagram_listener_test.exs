defmodule Xirsys.XTurn.DatagramListenerTest do
  use ExUnit.Case, async: false

  alias XSockets.{DatagramServer, Transport.UDP}
  alias Xirsys.XTurn.{DatagramListener, ListenRegistry}

  test "start_link registers the bound UDP socket for CHANGE-REQUEST" do
    opts = [
      transport: UDP,
      ip: {127, 0, 0, 1},
      port: 0,
      pipeline: Xirsys.XTurn.SocketPipeline.Datagram,
      assigns: %{transport: UDP}
    ]

    assert {:ok, pid} = DatagramListener.start_link(opts)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)

    {ip, port} = DatagramServer.endpoint(pid)
    assert {:ok, {UDP, socket}} = ListenRegistry.lookup({ip, port})
    assert socket == DatagramServer.socket(pid)
  end
end
