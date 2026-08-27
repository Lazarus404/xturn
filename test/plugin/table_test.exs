defmodule Xirsys.XTurn.Plugin.TableTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Plugin.Table
  alias Xirsys.XTurn.Tuple5

  setup do
    if :ets.whereis(Table) == :undefined do
      Table.init()
    end

    on_exit(fn ->
      for {key, _} <- :ets.tab2list(Table), do: :ets.delete(Table, key)
    end)

    :ok
  end

  test "normalises struct and egress map list to the same key" do
    struct =
      %Tuple5{
        client_address: {127, 0, 0, 1},
        client_port: 54_321,
        server_address: {127, 0, 0, 1},
        server_port: 3478,
        protocol: <<17, 0, 0, 0>>
      }

    egress =
      Tuple5.to_map(
        Tuple5.create(
          %Xirsys.XTurn.Conn{
            client_ip: {127, 0, 0, 1},
            client_port: 54_321,
            server_ip: {127, 0, 0, 1},
            server_port: 3478
          },
          :_
        )
      )

    assert Table.normalise(struct) == Table.normalise(egress)
  end

  test "put/get/delete round-trip uses normalised keys" do
    tuple5 =
      %Tuple5{
        client_address: {10, 0, 0, 1},
        client_port: 12_345,
        server_address: {10, 0, 0, 2},
        server_port: 3478,
        protocol: <<6, 0, 0, 0>>
      }

    chain = Xirsys.XTurn.Plugin.Chain.empty()
    :ok = Table.put(tuple5, chain)
    assert Table.get(tuple5) == chain

    map_key = Table.normalise(tuple5)
    assert Table.get(map_key) == chain

    :ok = Table.delete(tuple5)
    refute Table.get(tuple5)
  end
end
