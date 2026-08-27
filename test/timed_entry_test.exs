defmodule TimedEntryTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.TimedEntry

  test "replacing a key cancels the previous timer" do
    map = TimedEntry.put(%{}, :k, :v, 50, self(), :old)
    map = TimedEntry.put(map, :k, :v2, 5_000, self(), :new)

    assert {:ok, :v2} = TimedEntry.fetch(map, :k)
    refute_receive :old, 120
    refute_received :new
    TimedEntry.cancel_all(map)
  end
end
