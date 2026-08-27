defmodule DataPlaneTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias Xirsys.XTurn.DataPlane
  alias Xirsys.XTurn.Allocate.Store
  alias Xirsys.XTurn.Channels.Store, as: Channels
  alias Xirsys.XTurn.Permissions.Store, as: Permissions
  alias Xirsys.XTurn.Tuple5

  describe "classify/1" do
    test "ChannelData 0x4000..0x7FFF" do
      frame = <<0x4000::16, 4::16, "ping">>
      assert DataPlane.classify(frame) == {:channel, 0x4000, "ping"}
    end

    test "Binding request is control" do
      frame =
        Stun.encode(%Stun{
          class: :request,
          method: :binding,
          transactionid: 1,
          fingerprint: false,
          attrs: %{}
        })

      assert DataPlane.classify(frame) == :control
    end

    test "Send indication slim-decodes peer and data" do
      peer = {{10, 0, 0, 1}, 42_424}

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 99,
          fingerprint: false,
          attrs: %{xor_peer_address: peer, data: "payload"}
        })

      assert DataPlane.classify(frame) == {:send, peer, "payload"}
    end

    test "Send indication with integrity and fingerprint" do
      peer = {{127, 0, 0, 1}, 3480}
      key = :crypto.strong_rand_bytes(16)

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 123_456,
          integrity: true,
          key: key,
          fingerprint: true,
          attrs: %{xor_peer_address: peer, data: "hello"}
        })

      assert DataPlane.classify(frame) == {:send, peer, "hello"}
    end

    test "Refresh request is control" do
      frame =
        Stun.encode(%Stun{
          class: :request,
          method: :refresh,
          transactionid: 2,
          fingerprint: false,
          attrs: %{}
        })

      assert DataPlane.classify(frame) == :control
    end

    test "garbage is ignore" do
      assert DataPlane.classify(<<0xFF, 0xFF, 0x00>>) == :ignore
    end
  end

  describe "forward_channel/2" do
    setup do
      on_exit(fn ->
        Channels.delete_all(tuple5_map())
      end)

      :ok
    end

    test "relays payload to peer without ClientWorker" do
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, peer_port} = :inet.port(peer)
      {:ok, relay} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])

      Channels.insert(0x4001, self(), {{127, 0, 0, 1}, peer_port}, tuple5_struct(), relay, nil)

      meta = meta()
      frame = <<0x4001::16, 4::16, "ping">>

      assert :ok = DataPlane.forward_channel(frame, meta)
      assert {:ok, {_ip, _port, "ping"}} = :gen_udp.recv(peer, 0, 500)
      :gen_udp.close(peer)
      :gen_udp.close(relay)
    end

    test "drops on control connection" do
      meta = %{meta() | is_control: true}
      assert :drop = DataPlane.forward_channel(<<0x4001::16, 4::16, "ping">>, meta)
    end

    test "hairpins same-server channel data to dest client socket" do
      ctx = two_alloc_hairpin()
      Permissions.grant(Tuple5.to_map(ctx.t5_b), {127, 0, 0, 1})
      Channels.insert(0x4002, self(), ctx.dest_relay, ctx.t5_a, :relay, ctx.source_relay)

      assert :ok = DataPlane.forward_channel(<<0x4002::16, 4::16, "ping">>, ctx.meta_a)
      assert_receive {:turn_client, bin}
      assert {:ok, decoded} = Stun.decode(bin, nil)
      assert decoded.attrs.data == "ping"
      assert decoded.attrs.xor_peer_address == ctx.source_relay
      assert :gen_udp.recv(ctx.dest_relay_sock, 0, 50) == {:error, :timeout}
    end

    test "hairpin drops when dest has no permission for source IP" do
      ctx = two_alloc_hairpin()
      Channels.insert(0x4002, self(), ctx.dest_relay, ctx.t5_a, :relay, ctx.source_relay)

      assert :drop = DataPlane.forward_channel(<<0x4002::16, 4::16, "ping">>, ctx.meta_a)
      refute_received {:turn_client, _}
      assert :gen_udp.recv(ctx.dest_relay_sock, 0, 50) == {:error, :timeout}
    end
  end

  describe "forward_send/2" do
    setup do
      tid = "dp-send-#{System.unique_integer([:positive])}"
      client_port = System.unique_integer([:positive])

      on_exit(fn ->
        Store.delete(tid)
      end)

      {:ok, relay} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, peer_port} = :inet.port(peer)

      meta = meta(client_port)
      tuple5 = tuple5_for_meta(meta)
      Permissions.grant(Tuple5.to_map(tuple5), {127, 0, 0, 1})

      Store.insert(tid, self(), {{127, 0, 0, 1}, 9_999}, tuple5, relay, nil)

      on_exit(fn ->
        Permissions.revoke_all(Tuple5.to_map(tuple5))
        :gen_udp.close(relay)
        :gen_udp.close(peer)
      end)

      {:ok, tid: tid, peer: peer, peer_port: peer_port, relay: relay, meta: meta}
    end

    test "looks up allocation when listener sockname is unspecified" do
      tid = "dp-unspec-#{System.unique_integer([:positive])}"
      client_port = System.unique_integer([:positive])
      {:ok, relay} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, peer_port} = :inet.port(peer)

      meta = %{meta(client_port) | server_ip: {0, 0, 0, 0}}
      tuple5 = tuple5_for_meta(meta)
      assert tuple5.server_address != {0, 0, 0, 0}

      Permissions.grant(Tuple5.to_map(tuple5), {127, 0, 0, 1})
      Store.insert(tid, self(), {{127, 0, 0, 1}, 9_999}, tuple5, relay, nil)

      on_exit(fn ->
        Store.delete(tid)
        Permissions.revoke_all(Tuple5.to_map(tuple5))
        :gen_udp.close(relay)
        :gen_udp.close(peer)
      end)

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 7,
          fingerprint: false,
          attrs: %{xor_peer_address: {{127, 0, 0, 1}, peer_port}, data: "unspec"}
        })

      assert :ok = DataPlane.forward_send(frame, meta)
      assert {:ok, {_ip, _port, "unspec"}} = :gen_udp.recv(peer, 0, 500)
    end

    test "sends data when permission exists", %{peer: peer, peer_port: peer_port, meta: meta} do
      assert {:ok, _, _, _, _} =
               Store.lookup_tuple5(Tuple5.to_map(tuple5_for_meta(meta)))

      peer_addr = {{127, 0, 0, 1}, peer_port}

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 3,
          fingerprint: false,
          attrs: %{xor_peer_address: peer_addr, data: "relay-me"}
        })

      assert :ok = DataPlane.forward_send(frame, meta)
      assert {:ok, {_ip, _port, "relay-me"}} = :gen_udp.recv(peer, 0, 500)
    end

    test "missing permission is silent drop", %{peer_port: peer_port, meta: meta} do
      tuple5 = Tuple5.to_map(tuple5_for_meta(meta))
      Permissions.revoke(tuple5, {127, 0, 0, 1})
      peer_addr = {{127, 0, 0, 1}, peer_port}

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 4,
          fingerprint: false,
          attrs: %{xor_peer_address: peer_addr, data: "nope"}
        })

      assert :drop = DataPlane.forward_send(frame, meta)
    end

    test "hairpins send indication without UDP to dest relay port" do
      ctx = two_alloc_hairpin()
      Permissions.grant(Tuple5.to_map(ctx.t5_a), {127, 0, 0, 1})
      Permissions.grant(Tuple5.to_map(ctx.t5_b), {127, 0, 0, 1})
      Store.insert("src-send", self(), ctx.source_relay, ctx.t5_a, ctx.source_sock, nil)
      Store.publish_relays(
        self(),
        client_socket(),
        %{},
        ctx.t5_a,
        %{4 => %{socket: ctx.source_sock, address: ctx.source_relay, family: 4}}
      )

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 5,
          fingerprint: false,
          attrs: %{xor_peer_address: ctx.dest_relay, data: "hairpin"}
        })

      assert :ok = DataPlane.forward_send(frame, ctx.meta_a)
      assert_receive {:turn_client, bin}
      assert {:ok, decoded} = Stun.decode(bin, nil)
      assert decoded.attrs.data == "hairpin"
      assert decoded.attrs.xor_peer_address == ctx.source_relay
      assert :gen_udp.recv(ctx.dest_relay_sock, 0, 50) == {:error, :timeout}
    end

    test "send hairpin drops when dest has no permission for source IP" do
      ctx = two_alloc_hairpin()
      Permissions.grant(Tuple5.to_map(ctx.t5_a), {127, 0, 0, 1})
      Store.insert("src-send-noperm", self(), ctx.source_relay, ctx.t5_a, ctx.source_sock, nil)

      frame =
        Stun.encode(%Stun{
          class: :indication,
          method: :send,
          transactionid: 6,
          fingerprint: false,
          attrs: %{xor_peer_address: ctx.dest_relay, data: "nope"}
        })

      assert :drop = DataPlane.forward_send(frame, ctx.meta_a)
      refute_received {:turn_client, _}
      assert :gen_udp.recv(ctx.dest_relay_sock, 0, 50) == {:error, :timeout}
    end
  end

  describe "to_client/4" do
    test "encodes Data indication round-trip" do
      peer = {{192, 0, 2, 1}, 12_345}
      packet = "from-peer"

      bin = DataPlane.to_client(packet, peer, %{}, client_socket())

      assert {:ok, decoded} = Stun.decode(bin, nil)
      assert decoded.class == :indication
      assert decoded.method == :data
      assert decoded.attrs.data == packet
      assert decoded.attrs.xor_peer_address == peer
    end

    test "uses ChannelData when peer is bound" do
      peer = {{192, 0, 2, 2}, 54_321}
      packet = "chan"

      bin =
        DataPlane.to_client(packet, peer, %{peer => 0x4002}, client_socket())

      assert <<0x4002::16, 4::16, "chan">> = bin
    end
  end

  defp meta(client_port \\ 80) do
    %{
      client_ip: {127, 0, 0, 1},
      client_port: client_port,
      server_ip: {198, 162, 0, 1},
      server_port: 54_345,
      transport: XSockets.Transport.UDP,
      socket: :fake,
      is_control: false
    }
  end

  defp tuple5_for_meta(meta) do
    Tuple5.create(
      %Xirsys.XTurn.Conn{
        client_ip: meta.client_ip,
        client_port: meta.client_port,
        server_ip: meta.server_ip,
        server_port: meta.server_port,
        client_socket: nil
      },
      <<17, 0, 0, 0>>
    )
  end

  defp tuple5_struct do
    %Tuple5{
      client_address: {127, 0, 0, 1},
      client_port: 80,
      server_address: {198, 162, 0, 1},
      server_port: 54_345,
      protocol: :udp
    }
  end

  defp tuple5_map, do: Tuple5.to_map(tuple5_struct())

  defp client_socket do
    Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, self(), {127, 0, 0, 1}, 9999)
  end

  defp two_alloc_hairpin do
    {:ok, dest_relay_sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, dest_relay_port} = :inet.port(dest_relay_sock)
    dest_relay = {{127, 0, 0, 1}, dest_relay_port}

    {:ok, source_sock} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, source_port} = :inet.port(source_sock)
    source_relay = {{127, 0, 0, 1}, source_port}

    t5_a = %{tuple5_struct() | client_port: 10_001}
    t5_b = %{tuple5_struct() | client_port: 10_002}
    meta_a = %{meta() | client_port: 10_001}
    dest_client = client_socket()
    record = {self(), dest_client, %{}, Tuple5.to_map(t5_b)}

    :ets.insert(Store, {{:relay, dest_relay}, record})

    on_exit(fn ->
      :ets.delete(Store, {:relay, dest_relay})
      Store.delete("src-send")
      Store.delete("src-send-noperm")
      Permissions.revoke_all(Tuple5.to_map(t5_a))
      Permissions.revoke_all(Tuple5.to_map(t5_b))
      Channels.delete_all(t5_a)
      :gen_udp.close(dest_relay_sock)
      :gen_udp.close(source_sock)
    end)

    %{
      source_relay: source_relay,
      source_sock: source_sock,
      dest_relay: dest_relay,
      dest_relay_sock: dest_relay_sock,
      meta_a: meta_a,
      t5_a: t5_a,
      t5_b: t5_b
    }
  end
end
