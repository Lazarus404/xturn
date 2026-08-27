defmodule Xirsys.XTurn.ListenConfigTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.ListenConfig

  test "default_listen includes dual-stack plain and secure 5349" do
    listen = ListenConfig.default_listen(true)
    p = ListenConfig.turns_port()

    assert {:udp, ~c"0.0.0.0", 3478} in listen
    assert {:tcp, ~c"::", 3478} in listen
    assert {:udp, ~c"::", p, :secure} in listen
    assert {:tcp, ~c"0.0.0.0", p, :secure} in listen
  end

  test "secure_entries is empty when certs are not available" do
    assert ListenConfig.secure_entries(~c"0.0.0.0", false) == []
  end

  test "append_ipv6 adds v6 plain and secure listeners" do
    listen = ListenConfig.append_ipv6([], ~c"2001:db8::1", true)
    p = ListenConfig.turns_port()

    assert {:udp, ~c"2001:db8::1", 3478} in listen
    assert {:tcp, ~c"2001:db8::1", p, :secure} in listen
  end

  test "rewrite_ports maps plain to turn port and secure to turns port" do
    listen = [
      {:udp, ~c"0.0.0.0", 9999},
      {:tcp, ~c"::", 8888},
      {:udp, ~c"0.0.0.0", 7777, :secure},
      {:tcp, ~c"::", 6666, :secure}
    ]

    assert ListenConfig.rewrite_ports(listen, 3478, 443) ==
             [
               {:udp, ~c"0.0.0.0", 3478},
               {:tcp, ~c"::", 3478},
               {:udp, ~c"0.0.0.0", 443, :secure},
               {:tcp, ~c"::", 443, :secure}
             ]
  end

  test "default_listen never hardcodes 443" do
    listen = ListenConfig.default_listen(true)
    refute Enum.any?(listen, fn entry -> elem(entry, 2) == 443 end)
  end

  test "turn_port is 3478 when stun_port app env is explicitly nil" do
    saved = Application.get_env(:xturn, :stun_port)
    Application.put_env(:xturn, :stun_port, nil)

    on_exit(fn ->
      if is_nil(saved) do
        Application.delete_env(:xturn, :stun_port)
      else
        Application.put_env(:xturn, :stun_port, saved)
      end
    end)

    assert ListenConfig.turn_port() == 3478
  end
end
