defmodule ChannelStoreTest do
  # bring in the test functionality
  use ExUnit.Case

  alias Xirsys.XTurn.Channels.Store, as: S
  alias Xirsys.XTurn.Tuple5

  @valid_address {{127, 0, 0, 2}, 8888}
  @invalid_address {{127, 0, 0, 3}, 8889}
  @cid 12345
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
    t5 = new_tuple5()

    on_exit(fn ->
      S.delete(@cid, t5)
    end)

    pid = self()
    peer = @valid_address
    S.insert(@cid, pid, peer, t5)
    {:ok, tuple5: t5}
  end

  test "lookup entry by id, scoped to its allocation", %{tuple5: t5} do
    assert S.lookup(@cid, t5) == {:ok, {self(), @valid_address, nil, nil}}
    assert S.lookup(12346, t5) == {:error, :not_found}
  end

  test "lookup is insensitive to the allocation's original transport protocol", %{tuple5: t5} do
    wildcard_t5 = %Tuple5{t5 | protocol: :_}
    tcp_shaped_t5 = %Tuple5{t5 | protocol: <<6, 0, 0, 0>>}

    assert S.lookup(@cid, wildcard_t5) == {:ok, {self(), @valid_address, nil, nil}}
    assert S.lookup(@cid, tcp_shaped_t5) == {:ok, {self(), @valid_address, nil, nil}}
  end

  test "exists?/2 reflects presence", %{tuple5: t5} do
    assert S.exists?(@cid, t5)
    refute S.exists?(99999, t5)
  end

  test "delete/2 removes only the targeted channel, scoped to its allocation" do
    other_cid = 22222
    t5 = new_tuple5()
    S.insert(other_cid, self(), @invalid_address, t5)

    S.delete(@cid, t5)

    assert S.lookup(@cid, t5) == {:error, :not_found}
    assert S.lookup(other_cid, t5) == {:ok, {self(), @invalid_address, nil, nil}}

    S.delete(other_cid, t5)
  end

  test "delete_all/1 removes every channel belonging to one allocation, and no others" do
    t5_a = %Tuple5{new_tuple5() | client_address: {10, 0, 0, 1}, client_port: 1111}
    t5_b = %Tuple5{new_tuple5() | client_address: {10, 0, 0, 2}, client_port: 2222}

    S.insert(0x4000, self(), @valid_address, t5_a)
    S.insert(0x4001, self(), @invalid_address, t5_a)
    S.insert(0x4000, self(), @valid_address, t5_b)

    S.delete_all(t5_a)

    assert S.lookup(0x4000, t5_a) == {:error, :not_found}
    assert S.lookup(0x4001, t5_a) == {:error, :not_found}
    # a different allocation's identically-numbered channel must survive
    assert S.lookup(0x4000, t5_b) == {:ok, {self(), @valid_address, nil, nil}}

    S.delete_all(t5_b)
  end

  test "two allocations binding the same channel number do not clobber each other" do
    channel_number = 0x4000

    tuple5_a = %Tuple5{
      client_address: {10, 0, 0, 1},
      client_port: 1111,
      server_address: @sa,
      server_port: @sp,
      protocol: :_
    }

    tuple5_b = %Tuple5{
      client_address: {10, 0, 0, 2},
      client_port: 2222,
      server_address: @sa,
      server_port: @sp,
      protocol: :_
    }

    peer_a = {{10, 0, 0, 2}, 2222}
    peer_b = {{10, 0, 0, 1}, 1111}

    pid_a = spawn(fn -> Process.sleep(:infinity) end)
    pid_b = spawn(fn -> Process.sleep(:infinity) end)

    on_exit(fn ->
      S.delete(channel_number, tuple5_a)
      S.delete(channel_number, tuple5_b)
    end)

    S.insert(channel_number, pid_a, peer_a, tuple5_a)
    S.insert(channel_number, pid_b, peer_b, tuple5_b)

    assert S.lookup(channel_number, tuple5_a) == {:ok, {pid_a, peer_a, nil, nil}}
    assert S.lookup(channel_number, tuple5_b) == {:ok, {pid_b, peer_b, nil, nil}}
  end
end
