defmodule Xirsys.XTurn.Certs.WatcherTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.Certs.Watcher

  @poll_ms 20

  setup do
    dir = Path.join(System.tmp_dir!(), "xturn-cert-watch-#{System.unique_integer()}")
    File.mkdir_p!(dir)

    cert = Path.join(dir, "server.crt")
    key = Path.join(dir, "server.key")
    File.write!(cert, "cert-v1")
    File.write!(key, "key-v1")

    on_exit(fn -> File.rm_rf!(dir) end)

    %{dir: dir, cert: cert, key: key}
  end

  test "first poll records a baseline without reloading", ctx do
    _watcher =
      start_watcher(ctx,
        name: nil,
        reload_fun: fn -> send(self(), :reloaded) end
      )

    refute_receive :reloaded, @poll_ms * 2
  end

  test "unchanged content does not reload", ctx do
    reloads = start_watcher(ctx)

    Process.sleep(@poll_ms * 3)
    assert reloads.count.() == 0
  end

  test "a stable content change reloads exactly once", ctx do
    reloads = start_watcher(ctx)

    Process.sleep(@poll_ms * 2)
    File.write!(ctx.cert, "cert-v2")
    File.write!(ctx.key, "key-v2")

    assert poll_until(reloads, 1, @poll_ms * 10)
    Process.sleep(@poll_ms * 3)
    assert reloads.count.() == 1
  end

  test "a missing file is tolerated without crashing", ctx do
    reloads = start_watcher(ctx)

    Process.sleep(@poll_ms * 2)
    File.rm!(ctx.cert)

    Process.sleep(@poll_ms * 4)
    assert Process.alive?(reloads.pid)
    assert reloads.count.() == 0
  end

  # The polls below are driven by calling the callback directly rather than
  # waiting on the timer, so each step in the sequence is observed exactly once.
  describe "poll sequence" do
    test "content changing between polls does not reload until it stabilises", ctx do
      {state, count} = init_watcher(ctx)

      # Baseline.
      state = poll(state)
      assert count.() == 0

      # Cert replaced, key not yet: a mismatched pair must never be loaded.
      File.write!(ctx.cert, "cert-v2")
      state = poll(state)
      assert count.() == 0

      # Key replaced before the next poll: the hash moves again, still no reload.
      File.write!(ctx.key, "key-v2")
      state = poll(state)
      assert count.() == 0

      # Stable across two consecutive polls: reload fires now, and only once.
      state = poll(state)
      assert count.() == 1

      state = poll(state)
      assert count.() == 1

      # A later change still reloads, proving the debounce state was cleared.
      File.write!(ctx.cert, "cert-v3")
      File.write!(ctx.key, "key-v3")
      state = poll(state)
      assert count.() == 1

      _state = poll(state)
      assert count.() == 2
    end

    test "a missing file retains the baseline so restoring it does not reload", ctx do
      {state, count} = init_watcher(ctx)

      state = poll(state)
      assert count.() == 0

      cert = File.read!(ctx.cert)
      File.rm!(ctx.cert)

      state = poll(state)
      state = poll(state)
      assert count.() == 0

      # Same content back: the watcher must treat this as unchanged.
      File.write!(ctx.cert, cert)
      state = poll(state)
      _state = poll(state)
      assert count.() == 0
    end
  end

  defp init_watcher(ctx) do
    counter = :atomics.new(1, signed: false)

    {:ok, state} =
      Watcher.init(
        # Long enough that the timer never fires during the test; polls are
        # invoked explicitly instead.
        interval_ms: 3_600_000,
        paths: [ctx.cert, ctx.key],
        reload_fun: fn ->
          :atomics.add(counter, 1, 1)
          :ok
        end
      )

    {state, fn -> :atomics.get(counter, 1) end}
  end

  defp poll(state) do
    {:noreply, state} = Watcher.handle_info(:poll, state)
    state
  end

  defp start_watcher(ctx, opts \\ []) do
    reload_count = :atomics.new(1, signed: false)

    reload_fun =
      Keyword.get(opts, :reload_fun, fn ->
        :atomics.add(reload_count, 1, 1)
        :ok
      end)

    watcher_opts =
      [
        interval_ms: @poll_ms,
        paths: [ctx.cert, ctx.key],
        reload_fun: reload_fun,
        name: nil
      ]
      |> Keyword.merge(Keyword.drop(opts, [:reload_fun]))

    {:ok, pid} = start_supervised({Watcher, watcher_opts})

    %{
      pid: pid,
      count: fn -> :atomics.get(reload_count, 1) end
    }
  end

  defp poll_until(%{count: count}, expected, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms

    Stream.repeatedly(fn ->
      if count.() >= expected do
        true
      else
        Process.sleep(@poll_ms)
        false
      end
    end)
    |> Enum.reduce_while(false, fn
      true, _ -> {:halt, true}
      false, _ ->
        if System.monotonic_time(:millisecond) >= deadline do
          {:halt, false}
        else
          {:cont, false}
        end
    end)
  end
end
