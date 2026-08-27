defmodule TurnTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias Xirsys.XTurn.{Conn, Pipeline, Tuple5}
  alias Xirsys.XTurn.Auth.Client, as: Auth
  alias Xirsys.XTurn.Auth.SharedSecret
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient
  alias XSockets.Config

  @conn %Conn{
    client_ip: {127, 0, 0, 2},
    client_port: 8881,
    server_ip: {127, 0, 0, 1},
    server_port: 8882
  }

  @realm "xirsys.com"
  @username "some_user"
  @password "some_pass"
  # Auth.Client is a shared, stateful GenServer across tests in this module, so this
  # test uses its own username/password to avoid cross-test contamination with the
  # "allocates with authentication" test above, which reuses @username/@password.
  @integrity_username "real_integrity_user"
  @integrity_password "real_integrity_pass"

  test "allocates without authentication" do
    {:ok, orig_workers} = AllocateClient.count()
    # Dedicated 5-tuple: bare @conn is shared with "duplicate allocate" and other
    # suites; colliding here yields an idempotent success without a new worker,
    # so wait_until_worker_count(orig + 1) fails.
    no_auth_ip = {127, 0, 0, 3}
    stun = Stun.encode(allocation_request(100_000_003))

    conn =
      Pipeline.process_message(%Conn{
        @conn
        | message: stun,
          client_ip: no_auth_ip,
          client_socket: fake_client_socket()
      })

    assert conn.response.class == :success,
           "STUN request was successful"

    assert Map.get(conn.response.attrs, :xor_mapped_address) ==
             {no_auth_ip, @conn.client_port},
           "response has valid xor-mapped-address"

    assert Map.has_key?(conn.response.attrs, :xor_relayed_address),
           "response has valid xor-relayed-address"

    ip = Config.server_ip()
    {^ip, port} = Map.get(conn.response.attrs, :xor_relayed_address)

    assert is_integer(port),
           "assigned port is an integer"

    assert Map.get(conn.response.attrs, :lifetime) == <<600::32>>,
           "response contains a five minute TTL"

    assert wait_until_worker_count(orig_workers + 1),
           "an allocation worker has been created"
  end

  test "allocates with authentication" do
    {:ok, orig_workers} = AllocateClient.count()
    base = allocation_request()
    auth_ip = {127, 0, 0, 4}

    unauth_stun =
      Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, @username)))

    challenge =
      Pipeline.process_message(%Conn{
        @conn
        | message: unauth_stun,
          client_ip: auth_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    refute challenge.response.class == :success,
           "first request must not succeed"

    assert Map.has_key?(challenge.decoded_message.attrs || %{}, :realm),
           "failed authentication should return a realm"

    nonce = Map.get(challenge.decoded_message.attrs, :nonce)
    realm = Map.get(challenge.decoded_message.attrs, :realm)

    assert realm == @realm,
           "realm should be valid value for this TURN server"

    assert is_binary(nonce), "401 must include a fresh nonce"

    Auth.add_user(@username, @password, "/", "server")

    key = :crypto.hash(:md5, @username <> ":" <> @realm <> ":" <> @password)

    authed_attrs =
      base.attrs
      |> Map.put(:username, @username)
      |> Map.put(:realm, realm)
      |> Map.put(:nonce, nonce)

    authed_stun =
      Stun.encode(struct(base, attrs: authed_attrs, integrity: true, key: key))

    conn =
      Pipeline.process_message(%Conn{
        @conn
        | message: authed_stun,
          client_ip: auth_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    assert conn.response.class == :success,
           "STUN request was successful"

    assert Map.get(conn.response.attrs, :xor_mapped_address) ==
             {auth_ip, @conn.client_port},
           "response has valid xor-mapped-address"

    assert Map.has_key?(conn.response.attrs, :xor_relayed_address),
           "response has valid xor-relayed-address"

    ip = Config.server_ip()
    {^ip, port} = Map.get(conn.response.attrs, :xor_relayed_address)

    assert is_integer(port),
           "assigned port is an integer"

    assert Map.get(conn.response.attrs, :lifetime) == <<600::32>>,
           "response contains a five minute TTL"

    assert wait_until_worker_count(orig_workers + 1),
           "an allocation worker has been created"
  end

  test "allocates with a real MESSAGE-INTEGRITY footer (RFC 5389 long-term credential)" do
    {:ok, orig_workers} = AllocateClient.count()

    # Dedicated IP: reusing bare @conn's {client_ip, client_port} here would collide
    # with "allocates without authentication" (which never overrides client_ip) -
    # when that test runs first, this test's "unauthenticated" request matches its
    # already-existing allocation for that 5-tuple and gets a success response
    # straight from the duplicate-allocation path, without ever reaching
    # Authenticates.process/1 at all.
    integrity_ip = {127, 0, 0, 8}
    base = allocation_request()

    unauth_stun =
      Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, @integrity_username)))

    challenge =
      Pipeline.process_message(%Conn{
        @conn
        | message: unauth_stun,
          client_ip: integrity_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    refute challenge.response.class == :success, "first request must not succeed"
    nonce = Map.get(challenge.decoded_message.attrs, :nonce)
    realm = Map.get(challenge.decoded_message.attrs, :realm)
    assert realm == @realm

    Auth.add_user(@integrity_username, @integrity_password, "/", "server")

    key =
      :crypto.hash(:md5, @integrity_username <> ":" <> @realm <> ":" <> @integrity_password)

    authed_attrs =
      base.attrs
      |> Map.put(:username, @integrity_username)
      |> Map.put(:realm, realm)
      |> Map.put(:nonce, nonce)

    authed_stun =
      Stun.encode(struct(base, attrs: authed_attrs, integrity: true, key: key))

    conn =
      Pipeline.process_message(%Conn{
        @conn
        | message: authed_stun,
          client_ip: integrity_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    assert conn.response.class == :success,
           "authenticated request with a real MESSAGE-INTEGRITY footer must succeed"

    assert Map.has_key?(conn.response.attrs, :xor_relayed_address)

    assert wait_until_worker_count(orig_workers + 1)
  end

  test "retransmitted Allocate challenge keeps the same nonce so Chrome can authenticate" do
    {:ok, orig_workers} = AllocateClient.count()
    ip = {127, 0, 0, 16}
    base = allocation_request()
    unauth = Stun.encode(base)

    challenge1 =
      Pipeline.process_message(%Conn{
        @conn
        | message: unauth,
          client_ip: ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    challenge2 =
      Pipeline.process_message(%Conn{
        @conn
        | message: unauth,
          client_ip: ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    assert challenge1.response.err_no == 401
    assert challenge2.response.err_no == 401

    nonce = Map.get(challenge1.decoded_message.attrs, :nonce)
    realm = Map.get(challenge1.decoded_message.attrs, :realm)
    assert nonce == Map.get(challenge2.decoded_message.attrs, :nonce)

    key = :crypto.hash(:md5, "user" <> ":" <> @realm <> ":" <> "pass")

    authed =
      Stun.encode(
        struct(base, %{
          attrs: Map.merge(base.attrs, %{username: "user", realm: realm, nonce: nonce}),
          integrity: true,
          key: key
        })
      )

    conn =
      Pipeline.process_message(%Conn{
        @conn
        | message: authed,
          client_ip: ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    assert conn.response.class == :success
    assert Map.has_key?(conn.response.attrs, :xor_relayed_address)
    assert wait_until_worker_count(orig_workers + 1)
  end

  test "stale nonce returns 438 Stale Nonce" do
    old_max = Application.get_env(:xturn, :nonce_max_age_ms)
    Application.put_env(:xturn, :nonce_max_age_ms, 1)

    on_exit(fn ->
      Application.put_env(:xturn, :nonce_max_age_ms, old_max)
    end)

    stale_ip = {127, 0, 0, 14}
    base = allocation_request()

    challenge =
      Pipeline.process_message(%Conn{
        @conn
        | message: Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, "stale_user"))),
          client_ip: stale_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    nonce = Map.get(challenge.decoded_message.attrs, :nonce)
    realm = Map.get(challenge.decoded_message.attrs, :realm)
    Auth.add_user("stale_user", "stale_pass", "/", "server")

    key = :crypto.hash(:md5, "stale_user" <> ":" <> @realm <> ":" <> "stale_pass")

    authed_stun =
      Stun.encode(
        struct(base, %{
          attrs:
            base.attrs
            |> Map.put(:username, "stale_user")
            |> Map.put(:realm, realm)
            |> Map.put(:nonce, nonce),
          integrity: true,
          key: key
        })
      )

    Process.sleep(5)

    stale =
      Pipeline.process_message(%Conn{
        @conn
        | message: authed_stun,
          client_ip: stale_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    assert stale.response.err_no == 438
    assert stale.response.message == "Stale Nonce"
    assert is_binary(Map.get(stale.decoded_message.attrs, :nonce))
  end

  test "allocates with shared-secret credentials without Auth.add_user" do
    old_shared = Application.get_env(:xturn, :shared_secret)

    Application.put_env(:xturn, :shared_secret, [
      enabled: true,
      secret: "test-shared-secret",
      default_ttl_seconds: 86_400
    ])

    on_exit(fn -> Application.put_env(:xturn, :shared_secret, old_shared) end)

    {:ok, orig_workers} = AllocateClient.count()
    rest_ip = {127, 0, 0, 15}
    base = allocation_request()
    {username, password} = SharedSecret.generate("rest-user", 3600, "test-shared-secret")

    challenge =
      Pipeline.process_message(%Conn{
        @conn
        | message: Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, username))),
          client_ip: rest_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    nonce = Map.get(challenge.decoded_message.attrs, :nonce)
    realm = Map.get(challenge.decoded_message.attrs, :realm)
    key = :crypto.hash(:md5, username <> ":" <> @realm <> ":" <> password)

    authed_stun =
      Stun.encode(
        struct(base, %{
          attrs: base.attrs |> Map.put(:username, username) |> Map.put(:realm, realm) |> Map.put(:nonce, nonce),
          integrity: true,
          key: key
        })
      )

    conn =
      Pipeline.process_message(%Conn{
        @conn
        | message: authed_stun,
          client_ip: rest_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    assert conn.response.class == :success
    assert wait_until_worker_count(orig_workers + 1)
  end

  test "shared-secret and long-term credentials coexist" do
    old_shared = Application.get_env(:xturn, :shared_secret)

    Application.put_env(:xturn, :shared_secret, [
      enabled: true,
      secret: "test-shared-secret",
      default_ttl_seconds: 86_400
    ])

    on_exit(fn -> Application.put_env(:xturn, :shared_secret, old_shared) end)

    # Dedicated 5-tuples: {127,0,0,16} is used by the retransmit-nonce test; colliding
    # here skips Authenticates and leaves nonce nil, which crashes Stun.encode/1.
    assert {:ok, _} =
             authenticate_allocate(
               {127, 0, 0, 19},
               @integrity_username,
               @integrity_password,
               fn -> Auth.add_user(@integrity_username, @integrity_password, "/", "server") end,
               100_000_019
             )

    {rest_user, rest_pass} = SharedSecret.generate("coexist-rest", 3600, "test-shared-secret")

    assert {:ok, _} =
             authenticate_allocate({127, 0, 0, 22}, rest_user, rest_pass, fn -> :ok end, 100_000_022)
  end

  test "duplicate allocate reuses existing relay port" do
    {:ok, orig_workers} = AllocateClient.count()
    dup_ip = {127, 0, 0, 18}
    stun = Stun.encode(allocation_request(100_000_018))

    conn = %Conn{
      @conn
      | message: stun,
        client_ip: dup_ip,
        server_ip: {0, 0, 0, 0},
        client_socket: fake_client_socket()
    }

    first =
      Pipeline.process_message(conn)

    assert first.response.class == :success
    {_, first_port} = Map.get(first.response.attrs, :xor_relayed_address)

    second =
      Pipeline.process_message(%Conn{
        conn
        | decoded_message: struct(allocation_request(100_000_018), transactionid: 999_888_777_666)
      })

    assert second.response.class == :success
    {_, second_port} = Map.get(second.response.attrs, :xor_relayed_address)
    assert second_port == first_port

    assert wait_until_worker_count(orig_workers + 1)
  end

  test "refresh, createpermission, and channelbind all match an existing allocation via the :_ protocol wildcard" do
    dedicated_ip = {127, 0, 0, 9}
    stun = Stun.encode(allocation_request())

    allocate_conn = %Conn{
      @conn
      | message: stun,
        client_ip: dedicated_ip,
        client_socket: fake_client_socket()
    }

    allocated = Pipeline.process_message(allocate_conn)
    assert allocated.response.class == :success, "allocation must succeed"

    refresh_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :refresh,
          transactionid: 111_111_111_111,
          attrs: %{lifetime: <<300::32>>}
        })
      )

    refreshed =
      Pipeline.process_message(%Conn{allocate_conn | message: refresh_stun})

    assert refreshed.response.class == :success,
           "refresh should match the allocation regardless of protocol"

    assert Map.get(refreshed.response.attrs, :lifetime) == <<300::32>>

    createperm_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: 222_222_222_222,
          attrs: %{xor_peer_address: {{8, 8, 8, 8}, 12_345}}
        })
      )

    permed =
      Pipeline.process_message(%Conn{allocate_conn | message: createperm_stun})

    assert permed.response.class == :success,
           "createpermission should match the allocation regardless of protocol"

    channelbind_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: 333_333_333_333,
          attrs: %{
            channel_number: <<0x4000::16, 0::16>>,
            xor_peer_address: {{8, 8, 8, 8}, 12_345}
          }
        })
      )

    bound =
      Pipeline.process_message(%Conn{allocate_conn | message: channelbind_stun})

    assert bound.response.class == :success,
           "channelbind should match the allocation regardless of protocol"
  end

  test "channelbind followed by channeldata relays data to the bound peer without crashing" do
    dedicated_ip = {127, 0, 0, 12}
    peer_address = {{8, 8, 8, 9}, 45_000}
    channel_number = 0x4000

    stun = Stun.encode(allocation_request())

    allocate_conn = %Conn{
      @conn
      | message: stun,
        client_ip: dedicated_ip,
        client_socket: fake_client_socket()
    }

    allocated = Pipeline.process_message(allocate_conn)
    assert allocated.response.class == :success, "allocation must succeed"

    createperm_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: 666_111_222,
          attrs: %{xor_peer_address: peer_address}
        })
      )

    permed = Pipeline.process_message(%Conn{allocate_conn | message: createperm_stun})
    assert permed.response.class == :success, "createpermission must succeed"

    channelbind_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: 666_333_444,
          attrs: %{
            channel_number: <<channel_number::16, 0::16>>,
            xor_peer_address: peer_address
          }
        })
      )

    bound = Pipeline.process_message(%Conn{allocate_conn | message: channelbind_stun})
    assert bound.response.class == :success, "channelbind must succeed"

    channeldata_frame = <<channel_number::16, 4::16, "ping">>

    result = Pipeline.process_message(%Conn{allocate_conn | message: channeldata_frame})

    assert %Conn{} = result,
           "channeldata must not crash, and must find the channel bound above"
  end

  test "data arriving on the relay socket from a channel-bound peer reaches the client as ChannelData" do
    {:ok, server_udp} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, client_port} = :inet.port(server_udp)

    client_socket =
      Xirsys.XTurn.ClientSocket.new(
        XSockets.Transport.UDP,
        server_udp,
        {127, 0, 0, 1},
        client_port
      )

    dedicated_ip = {127, 0, 0, 31}
    channel_number = 0x4000

    allocate_conn = %Conn{
      @conn
      | message: Stun.encode(allocation_request()),
        client_ip: dedicated_ip,
        client_socket: client_socket
    }

    allocated = Pipeline.process_message(allocate_conn)
    assert allocated.response.class == :success, "allocation must succeed"
    {_relay_ip, relay_port} = Map.get(allocated.response.attrs, :xor_relayed_address)

    {:ok, peer_socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, peer_port} = :inet.port(peer_socket)
    peer_address = {{127, 0, 0, 1}, peer_port}

    createperm_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: 900_000_001,
          attrs: %{xor_peer_address: peer_address}
        })
      )

    permed = Pipeline.process_message(%Conn{allocate_conn | message: createperm_stun})
    assert permed.response.class == :success, "createpermission must succeed"

    channelbind_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: 900_000_002,
          attrs: %{
            channel_number: <<channel_number::16, 0::16>>,
            xor_peer_address: peer_address
          }
        })
      )

    bound = Pipeline.process_message(%Conn{allocate_conn | message: channelbind_stun})
    assert bound.response.class == :success, "channelbind must succeed"

    payload = "fake-rtp-payload"
    :ok = :gen_udp.send(peer_socket, {127, 0, 0, 1}, relay_port, payload)

    assert {:ok, {_ip, _port, data}} = :gen_udp.recv(server_udp, 0, 2_000)
    payload_size = byte_size(payload)

    assert <<^channel_number::16, ^payload_size::16, ^payload::binary>> = data,
           "peer data must reach the client wrapped as ChannelData on the bound channel"

    :gen_udp.close(peer_socket)
    :gen_udp.close(server_udp)
  end

  test "two concurrent allocations binding the same channel number both relay correctly" do
    ip_a = {127, 0, 0, 20}
    ip_b = {127, 0, 0, 21}
    channel_number = 0x4000

    conn_a = %Conn{@conn | client_ip: ip_a, client_socket: fake_client_socket()}
    conn_b = %Conn{@conn | client_ip: ip_b, client_socket: fake_client_socket()}

    # Each allocation needs its own STUN transaction id: Allocate.Store is keyed by
    # transactionid, and reusing one here would let B's insert clobber A's entry -
    # not a real-world concern since real transaction ids are random 96-bit values,
    # but it would matter for this test.
    allocate_stun_a =
      Stun.encode(struct(allocation_request(), %{transactionid: 700_000_010}))

    allocate_stun_b =
      Stun.encode(struct(allocation_request(), %{transactionid: 700_000_011}))

    allocated_a = Pipeline.process_message(%Conn{conn_a | message: allocate_stun_a})
    assert allocated_a.response.class == :success, "allocation A must succeed"

    allocated_b = Pipeline.process_message(%Conn{conn_b | message: allocate_stun_b})
    assert allocated_b.response.class == :success, "allocation B must succeed"

    peer_of_a = {ip_b, 45_000}
    peer_of_b = {ip_a, 45_001}

    createperm_a =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: 700_000_001,
          attrs: %{xor_peer_address: peer_of_a}
        })
      )

    createperm_b =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: 700_000_002,
          attrs: %{xor_peer_address: peer_of_b}
        })
      )

    permed_a = Pipeline.process_message(%Conn{conn_a | message: createperm_a})
    assert permed_a.response.class == :success

    permed_b = Pipeline.process_message(%Conn{conn_b | message: createperm_b})
    assert permed_b.response.class == :success

    channelbind_a =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: 700_000_003,
          attrs: %{
            channel_number: <<channel_number::16, 0::16>>,
            xor_peer_address: peer_of_a
          }
        })
      )

    channelbind_b =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: 700_000_004,
          attrs: %{
            channel_number: <<channel_number::16, 0::16>>,
            xor_peer_address: peer_of_b
          }
        })
      )

    # A binds first, then B binds the *same* channel number for its own,
    # different, allocation - this is what used to evict A's binding.
    bound_a = Pipeline.process_message(%Conn{conn_a | message: channelbind_a})
    assert bound_a.response.class == :success, "channelbind A must succeed"

    bound_b = Pipeline.process_message(%Conn{conn_b | message: channelbind_b})
    assert bound_b.response.class == :success, "channelbind B must succeed"

    channeldata_frame = <<channel_number::16, 4::16, "ping">>

    result_a = Pipeline.process_message(%Conn{conn_a | message: channeldata_frame})
    result_b = Pipeline.process_message(%Conn{conn_b | message: channeldata_frame})

    assert %Conn{} = result_a,
           "allocation A's channeldata must still resolve after B bound the same channel number"

    assert %Conn{} = result_b,
           "allocation B's channeldata must resolve on its own channel binding"

    # Explicitly tear down both allocations so they don't linger as extra workers
    # and race with other tests' worker-count assertions (see
    # "refresh with lifetime 0 ..." below for why this needs a poll rather than a
    # synchronous check).
    deallocate = fn tid ->
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :refresh,
          transactionid: tid,
          attrs: %{lifetime: <<0::32>>}
        })
      )
    end

    Pipeline.process_message(%Conn{conn_a | message: deallocate.(700_000_005)})
    Pipeline.process_message(%Conn{conn_b | message: deallocate.(700_000_006)})

    tuple5_a = Tuple5.to_map(Tuple5.create(conn_a, <<17, 0, 0, 0>>))
    tuple5_b = Tuple5.to_map(Tuple5.create(conn_b, <<17, 0, 0, 0>>))
    assert wait_until_deallocated(tuple5_a), "allocation A should be deallocated"
    assert wait_until_deallocated(tuple5_b), "allocation B should be deallocated"
  end

  test "refresh with lifetime 0 explicitly deallocates and still returns a success response" do
    dedicated_ip = {127, 0, 0, 10}
    stun = Stun.encode(allocation_request())

    allocate_conn = %Conn{
      @conn
      | message: stun,
        client_ip: dedicated_ip,
        client_socket: fake_client_socket()
    }

    allocated = Pipeline.process_message(allocate_conn)
    assert allocated.response.class == :success, "allocation must succeed"

    deallocate_stun =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :refresh,
          transactionid: 444_444_444_444,
          attrs: %{lifetime: <<0::32>>}
        })
      )

    deallocated =
      Pipeline.process_message(%Conn{allocate_conn | message: deallocate_stun})

    assert %Conn{} = deallocated, "must return a Conn struct, not the cast's bare :ok"
    assert deallocated.response.class == :success
    assert Map.get(deallocated.response.attrs, :lifetime) == <<0::32>>
    tuple5 = Tuple5.to_map(Tuple5.create(allocate_conn, <<17, 0, 0, 0>>))
    assert wait_until_deallocated(tuple5), "allocation should be deallocated"
  end

  defp wait_until_worker_count(expected, attempts \\ 50)

  defp wait_until_worker_count(_expected, 0), do: false

  defp wait_until_worker_count(expected, attempts) do
    case AllocateClient.count() do
      {:ok, count} when count >= expected ->
        true

      {:ok, _other} ->
        Process.sleep(10)
        wait_until_worker_count(expected, attempts - 1)
    end
  end

  defp wait_until_deallocated(tuple5, attempts \\ 50)

  defp wait_until_deallocated(_tuple5, 0), do: false

  defp wait_until_deallocated(tuple5, attempts) do
    case Store.lookup(tuple5) do
      {:error, :not_found} ->
        true

      {:ok, _} ->
        Process.sleep(10)
        wait_until_deallocated(tuple5, attempts - 1)
    end
  end

  defp allocation_request(transactionid \\ 123_456_789_012) do
    struct(Stun, %{
      class: :request,
      method: :allocate,
      transactionid: transactionid,
      attrs: %{requested_transport: <<17, 0, 0, 0>>}
    })
  end

  defp fake_client_socket do
    Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, :fake, {127, 0, 0, 1}, 9999)
  end

  defp authenticate_allocate(client_ip, username, password, setup_fun, transactionid \\ 123_456_789_012) do
    setup_fun.()
    base = allocation_request(transactionid)

    challenge =
      Pipeline.process_message(%Conn{
        @conn
        | message: Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, username))),
          client_ip: client_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    attrs = challenge.decoded_message.attrs || %{}
    nonce = Map.get(attrs, :nonce)
    realm = Map.get(attrs, :realm)

    unless is_binary(nonce) and is_binary(realm) do
      flunk(
        "expected 401 challenge with nonce/realm for #{inspect(client_ip)}, got class=#{inspect(challenge.response && challenge.response.class)} attrs=#{inspect(Map.keys(attrs))}"
      )
    end

    key = :crypto.hash(:md5, username <> ":" <> @realm <> ":" <> password)

    authed_stun =
      Stun.encode(
        struct(base, %{
          attrs:
            base.attrs
            |> Map.put(:username, username)
            |> Map.put(:realm, realm)
            |> Map.put(:nonce, nonce),
          integrity: true,
          key: key
        })
      )

    conn =
      Pipeline.process_message(%Conn{
        @conn
        | message: authed_stun,
          client_ip: client_ip,
          force_auth: true,
          client_socket: fake_client_socket()
      })

    if conn.response.class == :success do
      {:ok, conn}
    else
      {:error, conn}
    end
  end
end
