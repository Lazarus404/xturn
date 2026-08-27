defmodule ClientWorkerTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias XSockets.Conn, as: SockConn
  alias XSockets.Transport
  alias Xirsys.XTurn.ClientWorker.Pool
  alias Xirsys.XTurn.Handlers.StunTurn

  @server_ip {127, 0, 0, 1}

  test "per-client request ordering survives worker-pool dispatch" do
    {client_udp, client_ip, client_port} = open_client_socket()
    {listener, listener_port} = open_listener()

    sock_conn = sock_conn(listener, client_ip, client_port, listener_port)

    allocate = Stun.encode(allocation_request(100_001))
    assert :ok = dispatch_and_recv(allocate, sock_conn, client_udp, client_port)

    createperm =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: 100_002,
          attrs: %{xor_peer_address: {{8, 8, 8, 8}, 12_345}}
        })
      )

    assert :ok = dispatch_and_recv(createperm, sock_conn, client_udp, client_port)

    channelbind =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: 100_003,
          attrs: %{
            channel_number: <<0x4000::16, 0::16>>,
            xor_peer_address: {{8, 8, 8, 8}, 12_345}
          }
        })
      )

    assert :ok = dispatch_and_recv(channelbind, sock_conn, client_udp, client_port)

    :gen_udp.close(client_udp)
    :gen_udp.close(listener)
  end

  test "one client's burst load no longer delays another client's reply latency" do
    assert Pool.pool_size() >= 2,
           "test expects at least two workers (see config/test.exs client_worker_pool_size)"

    {flood_ip, flood_port, victim_ip, victim_port} = distinct_worker_clients()

    {:ok, flood_udp} =
      :gen_udp.open(flood_port, [:binary, active: false, ip: flood_ip, reuseaddr: true])

    {:ok, victim_udp} =
      :gen_udp.open(victim_port, [:binary, active: false, ip: victim_ip, reuseaddr: true])

    {listener, listener_port} = open_listener()

    flood_sock = sock_conn(listener, flood_ip, flood_port, listener_port)
    victim_sock = sock_conn(listener, victim_ip, victim_port, listener_port)

    flood_frame = Stun.encode(allocation_request(200_001))

    for _ <- 1..250 do
      assert {:ok, nil} = StunTurn.handle_packet(flood_frame, %{}, flood_sock, nil)
    end

    victim_frame = Stun.encode(allocation_request(200_002))
    started = System.monotonic_time(:millisecond)
    assert {:ok, nil} = StunTurn.handle_packet(victim_frame, %{}, victim_sock, nil)

    assert {:ok, {{127, 0, 0, 1}, ^listener_port, data}} = :gen_udp.recv(victim_udp, 0, 2_000)
    elapsed = System.monotonic_time(:millisecond) - started

    assert byte_size(data) > 0, "victim client should receive a STUN reply"
    assert elapsed < 500,
           "victim reply took #{elapsed}ms; expected well under flood backlog latency"

    :gen_udp.close(flood_udp)
    :gen_udp.close(victim_udp)
    :gen_udp.close(listener)
  end

  defp dispatch_and_recv(frame, sock_conn, client_udp, _client_port) do
    listener_port = sock_conn.server_port

    assert {:ok, nil} = StunTurn.handle_packet(frame, %{}, sock_conn, nil)

    case :gen_udp.recv(client_udp, 0, 2_000) do
      {:ok, {{127, 0, 0, 1}, ^listener_port, data}} ->
        assert byte_size(data) > 0
        :ok

      other ->
        flunk("expected STUN reply from listener port #{listener_port}, got #{inspect(other)}")
    end
  end

  defp open_client_socket do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: @server_ip])
    {:ok, port} = :inet.port(socket)
    {socket, @server_ip, port}
  end

  defp open_listener do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: @server_ip])
    {:ok, port} = :inet.port(socket)
    {socket, port}
  end

  defp sock_conn(listener, client_ip, client_port, listener_port) do
    %SockConn{
      socket: listener,
      client_ip: client_ip,
      client_port: client_port,
      server_ip: @server_ip,
      server_port: listener_port,
      assigns: %{transport: Transport.UDP}
    }
  end

  defp allocation_request(transaction_id) do
    struct(Stun, %{
      class: :request,
      method: :allocate,
      transactionid: transaction_id,
      attrs: %{requested_transport: <<17, 0, 0, 0>>}
    })
  end

  defp distinct_worker_clients do
    candidates =
      for port <- 40_000..40_500,
          ip = @server_ip do
        {ip, port, Pool.worker_index(ip, port)}
      end

    worker_zero = Enum.find(candidates, fn {_, _, idx} -> idx == 0 end)
    worker_one = Enum.find(candidates, fn {_, _, idx} -> idx == 1 end)

    assert worker_zero, "could not find a client tuple hashing to worker 0"
    assert worker_one, "could not find a client tuple hashing to worker 1"

    {ip_a, port_a, _} = worker_zero
    {ip_b, port_b, _} = worker_one
    {ip_a, port_a, ip_b, port_b}
  end
end
