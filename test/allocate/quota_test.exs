defmodule Xirsys.XTurn.Allocate.QuotaTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Allocate.Quota

  @table :xturn_alloc_quota

  test "concurrent first create does not crash on named ETS create" do
    if :ets.whereis(@table) != :undefined, do: :ets.delete(@table)

    parent = self()

    # Keep creators alive so the winning owner does not delete the table on exit.
    workers =
      for i <- 1..32 do
        spawn_link(fn ->
          result =
            try do
              Quota.init()
              Quota.increment("race_user_#{rem(i, 4)}")
              :ok
            rescue
              e -> {:error, e}
            end

          send(parent, {:done, result})
          receive do: (:stop -> :ok)
        end)
      end

    results =
      for _ <- 1..32 do
        receive do
          {:done, result} -> result
        after
          5_000 -> flunk("timed out waiting for concurrent Quota.init")
        end
      end

    assert Enum.all?(results, &(&1 == :ok))
    assert :ets.whereis(@table) != :undefined

    Enum.each(workers, &send(&1, :stop))
  end
end
