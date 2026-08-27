defmodule ClientTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Allocate.Client
  alias Xirsys.XTurn.Permissions.Store, as: Permissions
  alias Xirsys.XTurn.TimedEntry
  alias Xirsys.XTurn.{ClientSocket, Tuple5}

  test "permission expiry message does not crash the allocation" do
    {pid, tuple5} = start_alloc()
    peer_ip = {192, 168, 0, 6}
    assert :ok = Client.add_permissions(pid, peer_ip)
    assert Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)

    Permissions.stamp(
      Tuple5.to_map(tuple5),
      peer_ip,
      System.monotonic_time(:millisecond) - 301_000
    )
    send(pid, {:permission_expired, peer_ip})

    assert Process.alive?(pid)
    {:ok, perms} = Client.get_permission_cache(pid)
    refute TimedEntry.has_key?(perms, peer_ip)
    refute Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)
  end

  test "permission expiry is ignored when live traffic still has a fresh grant" do
    {pid, tuple5} = start_alloc()
    peer_ip = {192, 168, 0, 6}
    assert :ok = Client.add_permissions(pid, peer_ip)

    send(pid, {:permission_expired, peer_ip})

    assert Process.alive?(pid)
    {:ok, perms} = Client.get_permission_cache(pid)
    assert TimedEntry.has_key?(perms, peer_ip)
    assert Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)
  end

  test "channel expiry message does not crash the allocation" do
    {pid, _tuple5} = start_alloc()
    peer = {{192, 168, 0, 6}, 56_415}
    assert :ok = Client.bind_channel(pid, 0x4000, peer)

    send(pid, {:channel_expired, 0x4000})

    assert Process.alive?(pid)
    assert :ok = Client.bind_channel(pid, 0x4000, peer)
  end

  test "stale channel expiry does not unbind after a refresh" do
    {pid, _tuple5} = start_alloc()
    peer = {{192, 168, 0, 6}, 56_415}
    assert :ok = Client.bind_channel(pid, 0x4000, peer)
    assert :ok = Client.bind_channel(pid, 0x4000, peer)

    send(pid, {:channel_expired, 0x4000})

    assert Process.alive?(pid)

    assert {:ok, %Xirsys.XTurn.Channels.Channel{}} =
             TimedEntry.fetch(:sys.get_state(pid).channels, 0x4000)
  end

  test "ChannelBind on an existing channel restores permission state" do
    {pid, tuple5} = start_alloc()
    peer = {{192, 168, 0, 6}, 56_415}
    peer_ip = {192, 168, 0, 6}
    assert :ok = Client.bind_channel(pid, 0x4000, peer)

    Permissions.stamp(
      Tuple5.to_map(tuple5),
      peer_ip,
      System.monotonic_time(:millisecond) - 301_000
    )
    send(pid, {:permission_expired, peer_ip})
    {:ok, perms} = Client.get_permission_cache(pid)
    refute TimedEntry.has_key?(perms, peer_ip)
    refute Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)

    assert :ok = Client.bind_channel(pid, 0x4000, peer)
    assert Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)
    {:ok, perms} = Client.get_permission_cache(pid)
    assert TimedEntry.has_key?(perms, peer_ip)

    assert {:ok, %Xirsys.XTurn.Channels.Channel{}} =
             TimedEntry.fetch(:sys.get_state(pid).channels, 0x4000)
  end

  test "touch after expiry restores permission and extends the allocation" do
    {pid, tuple5} = start_alloc()
    peer_ip = {192, 168, 0, 6}
    assert :ok = Client.bind_channel(pid, 0x4000, {{192, 168, 0, 6}, 56_415})

    Permissions.stamp(
      Tuple5.to_map(tuple5),
      peer_ip,
      System.monotonic_time(:millisecond) - 301_000
    )
    send(pid, {:permission_expired, peer_ip})
    {:ok, _} = Client.get_permission_cache(pid)
    refute Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)

    Process.sleep(20)
    left_before = Xirsys.XTurn.Timing.milliseconds_left(:sys.get_state(pid))

    assert :ok = Client.touch(pid, peer_ip, 0x4000)
    {:ok, perms} = Client.get_permission_cache(pid)
    assert TimedEntry.has_key?(perms, peer_ip)
    assert Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)

    assert {:ok, %Xirsys.XTurn.Channels.Channel{}} =
             TimedEntry.fetch(:sys.get_state(pid).channels, 0x4000)

    left_after = Xirsys.XTurn.Timing.milliseconds_left(:sys.get_state(pid))
    assert left_after > left_before
  end

  test "touch refreshes permission even if the byte counter was unregistered" do
    {pid, tuple5} = start_alloc()
    peer_ip = {192, 168, 0, 6}
    assert :ok = Client.add_permissions(pid, peer_ip)

    Permissions.stamp(
      Tuple5.to_map(tuple5),
      peer_ip,
      System.monotonic_time(:millisecond) - 301_000
    )
    send(pid, {:permission_expired, peer_ip})
    {:ok, _} = Client.get_permission_cache(pid)
    refute Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)

    Xirsys.XTurn.Allocate.Bytes.unregister(pid)
    assert :ok = Client.touch(pid, peer_ip)
    {:ok, perms} = Client.get_permission_cache(pid)
    assert TimedEntry.has_key?(perms, peer_ip)
    assert Permissions.allowed?(Tuple5.to_map(tuple5), peer_ip)
  end

  defp start_alloc do
    port = System.unique_integer([:positive]) + 40_000

    tuple5 = %Tuple5{
      client_address: {127, 0, 0, 1},
      client_port: port,
      server_address: {127, 0, 0, 1},
      server_port: 3478,
      protocol: <<17, 0, 0, 0>>
    }

    client_socket = ClientSocket.new(XSockets.Transport.UDP, self(), {127, 0, 0, 1}, port)
    tid = "expire-#{System.unique_integer([:positive])}"
    {:ok, pid} = Client.start_link(tid, client_socket, tuple5, 600)

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid, :normal)
      Permissions.revoke_all(Tuple5.to_map(tuple5))
    end)

    {pid, tuple5}
  end
end
