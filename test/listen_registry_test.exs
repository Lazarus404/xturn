defmodule ListenRegistryTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.ListenRegistry
  alias XSockets.Transport.UDP

  test "first SO_REUSEPORT shard keeps the RFC 5780 socket" do
    endpoint = {{127, 0, 0, 1}, 61_001}
    ListenRegistry.ensure!()
    ListenRegistry.unregister(endpoint)

    assert :ok = ListenRegistry.register(endpoint, {UDP, :shard0})
    assert :ok = ListenRegistry.register(endpoint, {UDP, :shard1})
    assert {:ok, {UDP, :shard0}} = ListenRegistry.lookup(endpoint)

    ListenRegistry.unregister(endpoint)
  end
end
