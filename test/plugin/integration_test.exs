defmodule Xirsys.XTurn.Plugin.IntegrationTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias Xirsys.XTurn.{ClientSocket, Conn, Pipeline, Tuple5}
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Plugin.{Manager, Table}

  setup do
    old_plugins = Application.get_env(:xturn, :plugins)
    on_exit(fn -> restore_plugins(old_plugins) end)
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

  test "turn allocate succeeds with noop plugin configured and terminate clears chain" do
    Application.put_env(:xturn, :plugins, [{XTurn.TestSupport.PassthroughActive, []}])
    Manager.reload()

    {:ok, orig_workers} = AllocateClient.count()

    stun =
      Stun.encode(%Stun{
        class: :request,
        method: :allocate,
        transactionid: 987_654_321_098,
        attrs: %{requested_transport: <<17, 0, 0, 0>>}
      })

    conn =
      Pipeline.process_message(%Conn{
        client_ip: {127, 0, 0, 60},
        client_port: 55_001,
        server_ip: {127, 0, 0, 1},
        server_port: 8882,
        message: stun,
        client_socket: ClientSocket.new(XSockets.Transport.UDP, :fake, {127, 0, 0, 1}, 9999)
      })

    assert conn.response.class == :success

    tuple5 = Tuple5.create(conn, <<17, 0, 0, 0>>)
    {relay_ip, relay_port} = Map.fetch!(conn.response.attrs, :xor_relayed_address)

    assert Table.get(tuple5)
    assert {:ok, [pid, _tuple5, _socket, _perms]} = Store.lookup({relay_ip, relay_port})

    ref = Process.monitor(pid)
    assert :ok = AllocateClient.destroy(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 5_000

    assert {:error, :not_found} = Store.lookup({relay_ip, relay_port})
    assert wait_until_table_cleared(tuple5)
    assert wait_until_worker_count(orig_workers)
  end

  defp wait_until_table_cleared(tuple5, attempts \\ 50)
  defp wait_until_table_cleared(_tuple5, 0), do: false

  defp wait_until_table_cleared(tuple5, attempts) do
    if Table.get(tuple5) == nil do
      true
    else
      Process.sleep(20)
      wait_until_table_cleared(tuple5, attempts - 1)
    end
  end

  defp wait_until_worker_count(expected, attempts \\ 50)
  defp wait_until_worker_count(_expected, 0), do: false

  defp wait_until_worker_count(expected, attempts) do
    case AllocateClient.count() do
      {:ok, ^expected} -> true
      _ -> Process.sleep(20) && wait_until_worker_count(expected, attempts - 1)
    end
  end
end
