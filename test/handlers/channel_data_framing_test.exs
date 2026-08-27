defmodule ChannelDataFramingTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias XSockets.{Acceptor, DatagramServer, Transport}
  alias Xirsys.XTurn.{SocketPipeline, SocketPipeline.Datagram}
  alias Xirsys.XTurn.Plugin.Manager

  @loopback {127, 0, 0, 1}
  @channel_number 0x4000

  setup do
    {:ok, listener} =
      DatagramServer.start_link(
        transport: Transport.UDP,
        ip: @loopback,
        port: 0,
        pipeline: Datagram,
        assigns: %{transport: Transport.UDP}
      )

    server_port = DatagramServer.port(listener)

    {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, peer_port} = :inet.port(peer)

    on_exit(fn ->
      :gen_udp.close(client)
      :gen_udp.close(peer)
    end)

    %{
      listener: listener,
      server_port: server_port,
      client: client,
      peer: peer,
      peer_port: peer_port
    }
  end

  test "an unpadded, non-4-aligned ChannelData frame is relayed to the peer", ctx do
    relay_port = allocate(ctx, 880_000_001)
    create_permission(ctx, 880_000_002)
    bind_channel(ctx, 880_000_003)

    # 5 bytes: deliberately not a multiple of four, and sent with no padding,
    # exactly as Chrome frames relayed SRTP over UDP.
    payload = "12345"
    refute rem(byte_size(payload), 4) == 0, "payload must be non-4-aligned to be a regression test"

    frame = <<@channel_number::16, byte_size(payload)::16, payload::binary>>
    assert byte_size(frame) == 9
    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, frame)

    assert {:ok, {_ip, _port, relayed}} = :gen_udp.recv(ctx.peer, 0, 2_000)

    assert relayed == payload,
           "the peer must receive the exact payload, with no padding and nothing dropped"

    _ = relay_port
  end

  test "a non-4-aligned payload from the peer reaches the client as ChannelData", ctx do
    relay_port = allocate(ctx, 881_000_001)
    create_permission(ctx, 881_000_002)
    bind_channel(ctx, 881_000_003)

    payload = "abcdefg"
    refute rem(byte_size(payload), 4) == 0
    :ok = :gen_udp.send(ctx.peer, @loopback, relay_port, payload)

    assert {:ok, {_ip, _port, data}} = :gen_udp.recv(ctx.client, 0, 2_000)
    payload_size = byte_size(payload)

    assert <<@channel_number::16, ^payload_size::16, ^payload::binary>> = data,
           "peer data must arrive wrapped as ChannelData with an accurate length"
  end

  test "ingress transformer produces accurate ChannelData length", ctx do
    old_plugins = Application.get_env(:xturn, :plugins)

    on_exit(fn ->
      if old_plugins do
        Application.put_env(:xturn, :plugins, old_plugins)
      else
        Application.delete_env(:xturn, :plugins)
      end

      Manager.reload()
    end)

    Application.put_env(:xturn, :plugins, [{XTurn.TestSupport.TransformerActive, [suffix: "x"]}])
    Manager.reload()

    relay_port = allocate(ctx, 884_000_001)
    create_permission(ctx, 884_000_002)
    bind_channel(ctx, 884_000_003)

    payload = "abcdefg"
    refute rem(byte_size(payload), 4) == 0
    :ok = :gen_udp.send(ctx.peer, @loopback, relay_port, payload)

    assert {:ok, {_ip, _port, data}} = :gen_udp.recv(ctx.client, 0, 2_000)
    expected = payload <> "x"

    assert <<@channel_number::16, len::16, body::binary>> = data
    assert len == byte_size(body)
    assert body == expected
  end

  test "padded ChannelData is still accepted, and the padding is not relayed", ctx do
    _relay_port = allocate(ctx, 882_000_001)
    create_permission(ctx, 882_000_002)
    bind_channel(ctx, 882_000_003)

    payload = "12345"
    padding = <<0, 0, 0>>
    frame = <<@channel_number::16, byte_size(payload)::16, payload::binary, padding::binary>>
    assert rem(byte_size(frame), 4) == 0
    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, frame)

    assert {:ok, {_ip, _port, relayed}} = :gen_udp.recv(ctx.peer, 0, 2_000)

    assert relayed == payload,
           "alignment padding must be stripped rather than relayed as payload bytes"
  end

  test "peer data over TCP arrives as padded ChannelData on the wire", ctx do
    {:ok, acceptor} =
      Acceptor.start_link(
        transport: Transport.TCP,
        ip: @loopback,
        port: 0,
        pipeline: SocketPipeline,
        assigns: %{transport: Transport.TCP}
      )

    server_port = Acceptor.port(acceptor)
    {:ok, tcp_client} = :gen_tcp.connect(@loopback, server_port, [:binary, active: false])

    on_exit(fn ->
      :gen_tcp.close(tcp_client)
    end)

    relay_port = allocate_tcp(tcp_client, 883_000_001)
    create_permission_tcp(tcp_client, ctx, 883_000_002)
    bind_channel_tcp(tcp_client, ctx, 883_000_003)

    payload = "abcdefg"
    refute rem(byte_size(payload), 4) == 0
    :ok = :gen_udp.send(ctx.peer, @loopback, relay_port, payload)

    assert {:ok, channel, data, padding} = recv_channel_data_tcp(tcp_client, 2_000)
    assert channel == @channel_number
    assert data == payload
    assert padding > 0
    assert rem(4 + byte_size(data) + padding, 4) == 0
  end

  defp allocate(ctx, transaction_id) do
    request =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :allocate,
          transactionid: transaction_id,
          attrs: %{requested_transport: <<17, 0, 0, 0>>}
        })
      )

    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, request)

    assert {:ok, {_ip, _port, response}} = :gen_udp.recv(ctx.client, 0, 2_000)
    assert {:ok, turn} = Stun.decode(response)
    assert turn.class == :success, "allocation must succeed"

    {_relay_ip, relay_port} = Map.fetch!(turn.attrs, :xor_relayed_address)
    relay_port
  end

  defp create_permission(ctx, transaction_id) do
    request =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: transaction_id,
          attrs: %{xor_peer_address: {@loopback, ctx.peer_port}}
        })
      )

    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, request)

    assert {:ok, {_ip, _port, response}} = :gen_udp.recv(ctx.client, 0, 2_000)
    assert {:ok, %{class: :success}} = Stun.decode(response)
  end

  defp bind_channel(ctx, transaction_id) do
    request =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: transaction_id,
          attrs: %{
            channel_number: <<@channel_number::16, 0::16>>,
            xor_peer_address: {@loopback, ctx.peer_port}
          }
        })
      )

    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, request)

    assert {:ok, {_ip, _port, response}} = :gen_udp.recv(ctx.client, 0, 2_000)
    assert {:ok, %{class: :success}} = Stun.decode(response)
  end

  defp allocate_tcp(tcp, transaction_id) do
    request =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :allocate,
          transactionid: transaction_id,
          attrs: %{requested_transport: <<17, 0, 0, 0>>}
        })
      )

    :ok = :gen_tcp.send(tcp, request)
    assert {:ok, response} = recv_stun_tcp(tcp)
    assert {:ok, turn} = Stun.decode(response)
    assert turn.class == :success

    {_relay_ip, relay_port} = Map.fetch!(turn.attrs, :xor_relayed_address)
    relay_port
  end

  defp create_permission_tcp(tcp, ctx, transaction_id) do
    request =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :createperm,
          transactionid: transaction_id,
          attrs: %{xor_peer_address: {@loopback, ctx.peer_port}}
        })
      )

    :ok = :gen_tcp.send(tcp, request)
    assert {:ok, response} = recv_stun_tcp(tcp)
    assert {:ok, %{class: :success}} = Stun.decode(response)
  end

  defp bind_channel_tcp(tcp, ctx, transaction_id) do
    request =
      Stun.encode(
        struct(Stun, %{
          class: :request,
          method: :channelbind,
          transactionid: transaction_id,
          attrs: %{
            channel_number: <<@channel_number::16, 0::16>>,
            xor_peer_address: {@loopback, ctx.peer_port}
          }
        })
      )

    :ok = :gen_tcp.send(tcp, request)
    assert {:ok, response} = recv_stun_tcp(tcp)
    assert {:ok, %{class: :success}} = Stun.decode(response)
  end

  defp recv_stun_tcp(tcp, timeout \\ 2_000) do
    assert {:ok, <<0::2, _::14, body_bytes::16, _rest::binary>> = header} =
             :gen_tcp.recv(tcp, 20, timeout)

    total = body_bytes + 20

    if byte_size(header) == total do
      {:ok, header}
    else
      assert {:ok, rest} = :gen_tcp.recv(tcp, total - byte_size(header), timeout)
      {:ok, header <> rest}
    end
  end

  defp recv_channel_data_tcp(tcp, timeout) do
    assert {:ok, <<channel::16, len::16>>} = :gen_tcp.recv(tcp, 4, timeout)
    assert {:ok, payload} = :gen_tcp.recv(tcp, len, timeout)
    padding = pad_to_4(len) - len

    if padding == 0 do
      {:ok, channel, payload, 0}
    else
      assert {:ok, <<0::size(padding * 8)>>} = :gen_tcp.recv(tcp, padding, timeout)
      {:ok, channel, payload, padding}
    end
  end

  defp pad_to_4(n) when n <= 0, do: 0
  defp pad_to_4(n), do: Bitwise.band(n + 3, -4)
end
