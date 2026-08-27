defmodule AllocateStoreTest do
  # bring in the test functionality
  use ExUnit.Case
  # import ExUnit.CaptureIO # And allow us to capture stuff sent to stdout

  alias Xirsys.XTurn.Allocate.Store, as: S
  alias Xirsys.XTurn.Tuple5

  @valid_address {{127, 0, 0, 2}, 8888}
  @invalid_address {{127, 0, 0, 3}, 8889}
  @ca {127, 0, 0, 1}
  @cp 80
  @sa {198, 162, 0, 1}
  @sp 54345

  def new_tuple5 do
    %Xirsys.XTurn.Tuple5{
      client_address: @ca,
      client_port: @cp,
      server_address: @sa,
      server_port: @sp,
      protocol: :udp
    }
  end

  setup do
    tid = "12345"

    on_exit(fn ->
      S.delete(tid)
    end)

    pid = self()
    relay = @valid_address
    t5 = new_tuple5()
    S.insert(tid, pid, relay, t5, nil, nil)
    :ok
  end

  test "lookup entry by id" do
    assert S.lookup("12345") == {:ok, self(), nil, nil}
    assert S.lookup("12346") == {:error, :not_found}
  end

  test "lookup entry by relay address" do
    t5 = new_tuple5()
    normalized = Tuple5.to_map(%{t5 | protocol: :_})
    assert S.lookup(@valid_address) == {:ok, [self(), normalized, nil, nil]}
    assert S.lookup(@invalid_address) == {:error, :not_found}
  end

  test "lookup entry by 5 tuple" do
    t5 = new_tuple5()
    data = Tuple5.to_map(t5)
    assert S.lookup(data) == {:ok, [self(), @valid_address, nil, nil]}
    assert S.lookup_tuple5(data) == {:ok, self(), @valid_address, nil, nil}
    t5b = %{t5 | server_port: 54321}
    datb = Tuple5.to_map(t5b)
    assert S.lookup(datb) == {:error, :not_found}
    assert S.lookup_tuple5(datb) == {:error, :not_found}
  end

  test "tcp_allocation? follows REQUESTED-TRANSPORT at insert" do
    tid = "tcp-alloc"
    t5 = %{new_tuple5() | client_port: 81, protocol: <<6, 0, 0, 0>>}
    S.insert(tid, self(), {{127, 0, 0, 4}, 9}, t5, nil, nil)
    on_exit(fn -> S.delete(tid) end)

    assert S.tcp_allocation?(Tuple5.to_map(t5))
    refute S.tcp_allocation?(Tuple5.to_map(new_tuple5()))
  end

  test "lookup_relay and lookup_sock after publish_relays" do
    tid = "relay-pub"
    t5 = new_tuple5()
    {:ok, relay_sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, relay_port} = :inet.port(relay_sock)
    relay_addr = {{127, 0, 0, 1}, relay_port}
    client_socket = Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, :fake, {127, 0, 0, 1}, 1)

    on_exit(fn ->
      S.delete(tid)
      if is_port(relay_sock), do: :gen_udp.close(relay_sock)
    end)

    S.insert(tid, self(), relay_addr, t5, relay_sock, nil)

    S.publish_relays(
      self(),
      client_socket,
      %{},
      t5,
      %{4 => %{socket: relay_sock, address: relay_addr, family: 4}}
    )

    assert {:ok, dest} = S.lookup_relay(relay_addr)
    assert dest.pid == self()
    assert dest.client_socket == client_socket
    assert {:ok, ^dest} = S.lookup_sock(relay_sock)

    S.delete(tid)
    assert :error = S.lookup_relay(relay_addr)
    assert :error = S.lookup_sock(relay_sock)
  end
end
