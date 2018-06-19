defmodule TurnTest do

  use ExUnit.Case, async: false # bring in the test functionality
  require Logger

  alias Xirsys.Stun
  alias Xirsys.Turn.{Conn, Parse}
  alias Xirsys.Turn.Auth.Client, as: Auth
  alias Xirsys.Turn.Allocate.Client, as: AllocateClient

  @conn %Conn{
    client_ip: {127,0,0,2},
    client_port: 8881,
    server_ip: {127,0,0,1},
    server_port: 8882
  }
  @alternate_ip {127,0,0,3}
  @allocation %Stun{
    class: :request,
    method: :allocate,
    transactionid: 123456789012,
    attrs: [
      {:"REQUESTED-TRANSPORT", <<17, 0, 0, 0>>}
    ]
  }
  @realm "xirsys.com"
  @username "some_user"
  @password "some_pass"

  test "allocates without authentication" do
    # store the current number of allocation workers
    {:ok, orig_workers} = AllocateClient.count

    # create encoded STUN packet
    stun = Stun.encode(@allocation)
    # process
    conn = Parse.process_message(%Conn{@conn | message: stun})

    # response should be valid and contain reflexive IP and Port
    assert conn.response.class == :success,
      "STUN request was successful"
    assert :proplists.get_value(:"XOR-MAPPED-ADDRESS", conn.response.attrs) == {@conn.client_ip, @conn.client_port},
      "response has valid xor-mapped-address"
    assert :proplists.is_defined(:"XOR-RELAYED-ADDRESS", conn.response.attrs),
      "response has valid xor-relayed-address"

    # check an integer base port id is attributed
    ip = @conn.server_ip
    {^ip, port} = :proplists.get_value(:"XOR-RELAYED-ADDRESS", conn.response.attrs)

    assert is_integer(port),
      "assigned port is an integer"
    assert :proplists.get_value(:"LIFETIME", conn.response.attrs) == <<600::32>>,
      "response contains a five minute TTL"

    # assert that we now have one more allocation client
    {:ok, workers} = AllocateClient.count
    assert workers == orig_workers + 1,
      "an allocation worker has been created"
  end

  test "allocates with authentication" do
    # store the current number of allocation workers
    {:ok, orig_workers} = AllocateClient.count

    # as we're authenticating, apply user and pass
    attrs = @allocation.attrs ++ [{:"USERNAME", @username}, {:"PASSWORD", @password}]

    # create encoded STUN packet
    stun = Stun.encode(%Stun{@allocation | attrs: attrs})
    conn = Parse.process_message(%Conn{@conn | message: stun, client_ip: @alternate_ip, force_auth: true})

    # the first request should fail, but we need the returned realm to authenticate
    refute conn.response.class == :success,
      "first request must not succeed"
    assert :proplists.is_defined(:"REALM", conn.decoded_message.attrs || []),
      "failed authentication should return a realm"
    realm = :proplists.get_value(:"REALM", conn.decoded_message.attrs)
    assert realm == @realm,
      "realm should be valid value for this TURN server"

    # assign the realm to the attributes for the next pass
    attrs = attrs ++ [{:"REALM", realm}]

    # re-encode updated data
    stun = Stun.encode(%Stun{@allocation | attrs: attrs})
    # now we should add our user to the manifest, so it passes the lookup
    Auth.add_user(@username, @password, "/", "server")

    # second pass
    conn = Parse.process_message(%Conn{@conn | message: stun, client_ip: @alternate_ip, force_auth: true})

    # this should now pass and have an established relay address / port
    assert conn.response.class == :success,
      "STUN request was successful"
    assert :proplists.get_value(:"XOR-MAPPED-ADDRESS", conn.response.attrs) == {@alternate_ip, @conn.client_port},
      "response has valid xor-mapped-address"
    assert :proplists.is_defined(:"XOR-RELAYED-ADDRESS", conn.response.attrs),
      "response has valid xor-relayed-address"

    # validate an assigned port and that it's an integer
    ip = @conn.server_ip
    {^ip, port} = :proplists.get_value(:"XOR-RELAYED-ADDRESS", conn.response.attrs)

    assert is_integer(port),
      "assigned port is an integer"
    assert :proplists.get_value(:"LIFETIME", conn.response.attrs) == <<600::32>>,
      "response contains a five minute TTL"

    # assert that we now have one more allocation client
    {:ok, workers} = AllocateClient.count
    assert workers == orig_workers + 1,
      "an allocation worker has been created"
  end
end