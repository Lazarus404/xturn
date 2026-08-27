defmodule Xirsys.XTurn.Plugin.DispatchTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Plugin.{Chain, Dispatch, Lifecycle, Manager, Table}
  alias Xirsys.XTurn.Plugin.Allocation
  alias Xirsys.XTurn.Tuple5

  @peer {127, 0, 0, 1}
  @peer_port 50_000
  @payload "hello"

  @test_modules [
    XTurn.TestSupport.PassthroughActive,
    XTurn.TestSupport.TransformerActive,
    XTurn.TestSupport.DropperActive,
    XTurn.TestSupport.RaiserActive,
    XTurn.TestSupport.BlockingPassive,
    XTurn.TestSupport.ClosingPassive,
    XTurn.TestSupport.DecliningActive,
    XTurn.TestSupport.IgnoringActive,
    XTurn.TestSupport.SlowActive,
    XTurn.TestSupport.CrashingPassive
  ]

  setup do
    old_plugins = Application.get_env(:xturn, :plugins)
    on_exit(fn -> restore_plugins(old_plugins) end)

    if :ets.whereis(Table) == :undefined do
      Table.init()
    end

    for {key, _} <- :ets.tab2list(Table), do: :ets.delete(Table, key)

    reset_plugin_state()
    :persistent_term.put({Xirsys.XTurn.Plugin, :enabled}, false)
    :ok
  end

  defp restore_plugins(old_plugins) do
    if old_plugins do
      Application.put_env(:xturn, :plugins, old_plugins)
    else
      Application.delete_env(:xturn, :plugins)
    end

    Manager.reload()
  end

  defp reset_plugin_state do
    for mod <- @test_modules do
      :persistent_term.put({Xirsys.XTurn.Plugin, :disabled, mod}, false)
      :persistent_term.put({Xirsys.XTurn.Plugin.Dispatch, :sample_counter, mod}, :atomics.new(1, signed: false))
      :persistent_term.put({Xirsys.XTurn.Plugin.Dispatch, :mean_ref, mod}, :atomics.new(1, signed: false))
    end
  end

  defp tuple5_key do
    Table.normalise(
      %Tuple5{
        client_address: {127, 0, 0, 1},
        client_port: 54_321,
        server_address: {127, 0, 0, 1},
        server_port: 3478,
        protocol: <<17, 0, 0, 0>>
      }
    )
  end

  defp sample_allocation do
    %Allocation{
      id: <<0::96>>,
      tuple5: tuple5_key(),
      client_ip: {127, 0, 0, 1},
      client_port: 54_321,
      server_ip: {127, 0, 0, 1},
      server_port: 3478,
      protocol: <<17, 0, 0, 0>>,
      relay_address: {{127, 0, 0, 1}, 60_000},
      transport: XSockets.Transport.UDP,
      started_at: DateTime.utc_now()
    }
  end

  defp enable_plugins!(plugins) do
    Application.put_env(:xturn, :plugins, plugins)
    Manager.reload()
  end

  defp put_chain!(chain) do
    :persistent_term.put({Xirsys.XTurn.Plugin, :enabled}, true)
    :ok = Table.put(tuple5_key(), chain)
  end

  test "disabled dispatch returns payload unchanged without table lookup" do
    :persistent_term.put({Xirsys.XTurn.Plugin, :enabled}, false)

    refute Table.get(tuple5_key())

    assert Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil) ==
             {:ok, @payload}

    assert Dispatch.ingress(tuple5_key(), @payload, :data_indication, {@peer, @peer_port}) ==
             {:ok, @payload}
  end

  test "active chain composes in config order" do
    put_chain!(%Chain{
      egress_active: [
        {XTurn.TestSupport.TransformerActive, "a", [suffix: "a"]},
        {XTurn.TestSupport.TransformerActive, "b", [suffix: "b"]}
      ]
    })

    assert Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil) ==
             {:ok, "helloab"}
  end

  test "drop short-circuits the active chain" do
    put_chain!(%Chain{
      egress_active: [
        {XTurn.TestSupport.DropperActive, nil, []},
        {XTurn.TestSupport.TransformerActive, "x", [suffix: "x"]}
      ]
    })

    assert Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil) ==
             :drop
  end

  test "raising plugin passes through with fail open and drops with fail closed" do
    put_chain!(%Chain{
      egress_active: [{XTurn.TestSupport.RaiserActive, nil, [fail: :open]}]
    })

    assert Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil) ==
             {:ok, @payload}

    put_chain!(%Chain{
      egress_active: [{XTurn.TestSupport.RaiserActive, nil, [fail: :closed]}]
    })

    assert Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil) ==
             :drop
  end

  test "passive backpressure drops when max_inflight is exceeded" do
    enable_plugins!([{XTurn.TestSupport.BlockingPassive, max_inflight: 1}])
    Lifecycle.allocation_started(sample_allocation())

    chain = Table.get(tuple5_key())
    [{_mod, pid, _ref, _max}] = chain.egress_passive

    handler_id =
      :telemetry.attach(
        "plugin-passive-dropped-test",
        [:xturn, :plugin, :passive, :dropped],
        fn _event, measurements, _metadata, test_pid ->
          send(test_pid, {:dropped, measurements})
        end,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert {:ok, @payload} =
             Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil)

    assert Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil) ==
             {:ok, @payload}

    assert_receive {:dropped, %{bytes: 5, inflight: 2}}

    send(pid, :release)
    Lifecycle.allocation_ended(tuple5_key(), :test)
  end

  test "lifecycle attaches a no-op active plugin" do
    enable_plugins!([{XTurn.TestSupport.PassthroughActive, []}])
    Lifecycle.allocation_started(sample_allocation())

    chain = Table.get(tuple5_key())
    assert [{XTurn.TestSupport.PassthroughActive, _, _}] = chain.egress_active
    assert [{XTurn.TestSupport.PassthroughActive, _, _}] = chain.ingress_active

    assert Dispatch.egress(tuple5_key(), @payload, :channel_data, {@peer, @peer_port}, 1) ==
             {:ok, @payload}

    Lifecycle.allocation_ended(tuple5_key(), :test)
    refute Table.get(tuple5_key())
  end

  test "handle_close/2 runs with the allocation's own teardown reason" do
    enable_plugins!([{XTurn.TestSupport.ClosingPassive, notify: self()}])
    Lifecycle.allocation_started(sample_allocation())

    Lifecycle.allocation_ended(tuple5_key(), :peer_gone)

    assert_receive {:closed, :peer_gone},
                   1_000,
                   "handle_close must see the real reason, not the supervisor's :shutdown"
  end

  test "allocation owner dying tears the chain down" do
    enable_plugins!([{XTurn.TestSupport.ClosingPassive, notify: self()}])

    owner = spawn(fn -> Process.sleep(:infinity) end)
    Lifecycle.allocation_started(%Allocation{sample_allocation() | owner_pid: owner})

    assert Table.get(tuple5_key())

    Process.exit(owner, :kill)

    assert_receive {:closed, :killed}, 1_000
    assert wait_until(fn -> Table.get(tuple5_key()) == nil end)
  end

  test "attach? returning false yields an empty chain" do
    enable_plugins!([{XTurn.TestSupport.DecliningActive, []}])
    Lifecycle.allocation_started(sample_allocation())

    chain = Table.get(tuple5_key())
    assert chain.egress_active == []
    assert chain.ingress_active == []
    assert chain.egress_passive == []
    assert chain.ingress_passive == []

    Lifecycle.allocation_ended(tuple5_key(), :test)
  end

  test "init returning :ignore yields an empty chain" do
    enable_plugins!([{XTurn.TestSupport.IgnoringActive, []}])
    Lifecycle.allocation_started(sample_allocation())

    chain = Table.get(tuple5_key())
    assert chain.egress_active == []
    assert chain.ingress_active == []

    Lifecycle.allocation_ended(tuple5_key(), :test)
  end

  test "crashed passive instance is pruned and active chain keeps working" do
    enable_plugins!([
      {XTurn.TestSupport.PassthroughActive, []},
      {XTurn.TestSupport.CrashingPassive, []}
    ])

    Lifecycle.allocation_started(sample_allocation())

    assert {:ok, @payload} =
             Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil)

    assert wait_until(fn ->
             chain = Table.get(tuple5_key())
             chain != nil and chain.egress_passive == []
           end)

    assert {:ok, @payload} =
             Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil)

    Lifecycle.allocation_ended(tuple5_key(), :test)
  end

  test "circuit breaker disables slow active plugin and skips it thereafter" do
    for {name, event} <- [
          {"plugin-active-disabled-test", [:xturn, :plugin, :active, :disabled]},
          {"plugin-active-stop-test", [:xturn, :plugin, :active, :stop]}
        ] do
      :telemetry.attach(
        name,
        event,
        fn event_name, measurements, metadata, test_pid ->
          send(test_pid, {:telemetry, event_name, measurements, metadata})
        end,
        self()
      )

      on_exit(fn -> :telemetry.detach(name) end)
    end

    # A transformer sits behind the slow plugin so "was it skipped" is observable
    # from the payload, not just from the absence of telemetry.
    put_chain!(%Chain{
      egress_active: [
        {XTurn.TestSupport.SlowActive, 5, [sample_every: 1, budget_us: 0, sleep_ms: 5]},
        {XTurn.TestSupport.TransformerActive, "t", [suffix: "t"]}
      ]
    })

    assert {:ok, "hellot"} =
             Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil)

    assert_receive {:telemetry, [:xturn, :plugin, :active, :stop], _, _}

    assert_receive {:telemetry, [:xturn, :plugin, :active, :disabled], %{mean_us: mean_us},
                    %{module: XTurn.TestSupport.SlowActive}}

    assert mean_us > 0
    assert :persistent_term.get({Xirsys.XTurn.Plugin, :disabled, XTurn.TestSupport.SlowActive})

    # Drain anything still queued from the first frame before proving the second
    # one never reaches the disabled plugin.
    flush_telemetry()

    assert {:ok, "hellot"} =
             Dispatch.egress(tuple5_key(), @payload, :send_indication, {@peer, @peer_port}, nil)

    refute_receive {:telemetry, [:xturn, :plugin, :active, :stop], _,
                    %{module: XTurn.TestSupport.SlowActive}},
                   200,
                   "a disabled plugin must not be invoked again"
  end

  defp flush_telemetry do
    receive do
      {:telemetry, _, _, _} -> flush_telemetry()
    after
      0 -> :ok
    end
  end

  defp wait_until(fun, attempts \\ 50)
  defp wait_until(_fun, 0), do: false

  defp wait_until(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(20)
      wait_until(fun, attempts - 1)
    end
  end
end
