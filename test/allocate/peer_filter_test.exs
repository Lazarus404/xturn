defmodule Xirsys.XTurn.PeerFilterTest do
  use ExUnit.Case, async: true

  alias XSockets.Config
  alias Xirsys.XTurn.PeerFilter

  test "same-IP peer is forbidden unless the IP is the advertised TURN address" do
    assert PeerFilter.forbidden?({{203, 0, 113, 50}, 50000}, {203, 0, 113, 50}, [])
  end

  test "hairpin to a non-listen port on the advertised IP is allowed" do
    ip = Config.server_ip()
    refute PeerFilter.forbidden?({ip, 54_149}, ip, [])
  end

  test "the TURN listen port on the advertised IP is forbidden" do
    ip = Config.server_ip()
    assert PeerFilter.forbidden?({ip, 3478}, {127, 0, 0, 1}, [])
  end
end
