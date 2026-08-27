defmodule Allocate.BytesTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.Allocate.Bytes

  setup do
    Bytes.init()
    pid = self()
    Bytes.register(pid)
    on_exit(fn -> Bytes.unregister(pid) end)
    :ok
  end

  test "tracks outbound bytes without GenServer casts" do
    Bytes.add_out(self(), 100)
    Bytes.add_out(self(), 50)
    state = %{bytes_in: 10, bytes_out: 5}
    merged = Bytes.merge(state, self())
    assert merged.bytes_in == 10
    assert merged.bytes_out == 155
  end

  test "tracks inbound bytes" do
    Bytes.add_in(self(), 42)
    merged = Bytes.merge(%{bytes_in: 0, bytes_out: 0}, self())
    assert merged.bytes_in == 42
  end
end
