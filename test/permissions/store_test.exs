defmodule Permissions.StoreTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Permissions.Store

  setup do
    Store.init()
    tuple5 = [{:ca, {10, 0, 0, 1}}, {:cp, 9}, {:sa, {10, 0, 0, 2}}, {:sp, 3478}, {:proto, :udp}]
    on_exit(fn -> Store.revoke_all(tuple5) end)
    {:ok, tuple5: tuple5}
  end

  test "allowed? is an O(1) member check", %{tuple5: tuple5} do
    peer = {203, 0, 113, 1}
    refute Store.allowed?(tuple5, peer)
    Store.grant(tuple5, peer)
    assert Store.allowed?(tuple5, peer)
    Store.revoke(tuple5, peer)
    refute Store.allowed?(tuple5, peer)
  end

  test "due_refresh? is true when missing and false while the grant is fresh", %{tuple5: tuple5} do
    peer = {203, 0, 113, 2}
    assert Store.due_refresh?(tuple5, peer)
    Store.grant(tuple5, peer)
    refute Store.due_refresh?(tuple5, peer)
    assert Store.due_refresh?(tuple5, peer, 0)
  end
end
