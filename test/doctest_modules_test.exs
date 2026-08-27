defmodule Xirsys.XTurn.DoctestModulesTest do
  use ExUnit.Case, async: true

  doctest Xirsys.XTurn.Timing
  doctest Xirsys.XTurn.TimedEntry
  doctest Xirsys.XTurn.AddressFamily
  doctest Xirsys.XTurn.RelayFamily
  doctest Xirsys.XTurn.PeerFilter
  doctest Xirsys.XTurn.Tuple5
  doctest Xirsys.XTurn.DataPlane
  doctest Xirsys.XTurn.DualIp
  doctest Xirsys.XTurn.Auth.UUID
  doctest Xirsys.XTurn.Auth.AccessToken
  doctest Xirsys.XTurn.Auth.SharedSecret
end
