defmodule RateLimitTest do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias XSockets.{DatagramServer, Transport}
  alias Xirsys.XTurn.SocketPipeline

  @loopback {127, 0, 0, 1}
  @channel_number 0x4000
  @max_requests 10

  setup do
    previous = %{
      enabled: Application.get_env(:xturn, :rate_limit_enabled),
      max: Application.get_env(:xturn, :max_requests_per_window)
    }

    Application.put_env(:xturn, :rate_limit_enabled, true)
    Application.put_env(:xturn, :max_requests_per_window, @max_requests)

    # The limiter's ETS table outlives individual tests, so start from a clean
    # budget rather than inheriting counts from earlier cases.
    case :ets.whereis(:xsockets_rate_limits) do
      :undefined -> :ok
      table -> :ets.delete_all_objects(table)
    end

    {:ok, listener} =
      DatagramServer.start_link(
        transport: Transport.UDP,
        ip: @loopback,
        port: 0,
        pipeline: SocketPipeline.Datagram,
        assigns: %{transport: Transport.UDP}
      )

    {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: @loopback])
    {:ok, peer_port} = :inet.port(peer)

    on_exit(fn ->
      :gen_udp.close(client)
      :gen_udp.close(peer)
      restore(:rate_limit_enabled, previous.enabled)
      restore(:max_requests_per_window, previous.max)
    end)

    %{
      server_port: DatagramServer.port(listener),
      client: client,
      peer: peer,
      peer_port: peer_port
    }
  end

  test "sustained relayed media is never throttled", ctx do
    setup_channel(ctx, 890_000_000)

    # Far more media frames than the request budget allows. Every one must be
    # relayed: ChannelData is not a request and must not consume the budget.
    media_frames = @max_requests * 5

    for index <- 1..media_frames do
      payload = "media-#{index}"
      frame = <<@channel_number::16, byte_size(payload)::16, payload::binary>>
      :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, frame)
    end

    relayed = drain_peer(ctx.peer, media_frames)

    assert length(relayed) == media_frames,
           "expected all #{media_frames} media frames to be relayed, got #{length(relayed)}"

    assert "media-#{media_frames}" in relayed, "the last frame must still get through"
  end

  test "control-plane requests are throttled once the budget is spent", ctx do
    # Each Binding request is a STUN request, so it draws on the budget.
    accepted =
      Enum.count(1..(@max_requests * 2), fn index ->
        request =
          Stun.encode(
            struct(Stun, %{
              class: :request,
              method: :binding,
              transactionid: 891_000_000 + index
            })
          )

        :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, request)

        match?({:ok, _}, :gen_udp.recv(ctx.client, 0, 200))
      end)

    assert accepted == @max_requests,
           "expected exactly the budgeted #{@max_requests} requests to be answered, got #{accepted}"
  end

  defp setup_channel(ctx, base_transaction_id) do
    allocate = request(:allocate, base_transaction_id + 1, %{requested_transport: <<17, 0, 0, 0>>})
    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, allocate)
    assert {:ok, {_, _, response}} = :gen_udp.recv(ctx.client, 0, 2_000)
    assert {:ok, %{class: :success}} = Stun.decode(response)

    peer_address = %{xor_peer_address: {@loopback, ctx.peer_port}}

    createperm = request(:createperm, base_transaction_id + 2, peer_address)
    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, createperm)
    assert {:ok, {_, _, perm_resp}} = :gen_udp.recv(ctx.client, 0, 2_000)
    assert {:ok, %{class: :success}} = Stun.decode(perm_resp)

    channelbind =
      request(
        :channelbind,
        base_transaction_id + 3,
        Map.put(peer_address, :channel_number, <<@channel_number::16, 0::16>>)
      )

    :ok = :gen_udp.send(ctx.client, @loopback, ctx.server_port, channelbind)
    assert {:ok, {_, _, bind_resp}} = :gen_udp.recv(ctx.client, 0, 2_000)
    assert {:ok, %{class: :success}} = Stun.decode(bind_resp)
  end

  defp request(method, transaction_id, attrs) do
    Stun.encode(
      struct(Stun, %{
        class: :request,
        method: method,
        transactionid: transaction_id,
        attrs: attrs
      })
    )
  end

  defp drain_peer(socket, expected, acc \\ [])

  defp drain_peer(_socket, 0, acc), do: Enum.reverse(acc)

  defp drain_peer(socket, remaining, acc) do
    case :gen_udp.recv(socket, 0, 500) do
      {:ok, {_ip, _port, data}} -> drain_peer(socket, remaining - 1, [data | acc])
      {:error, :timeout} -> Enum.reverse(acc)
    end
  end

  defp restore(key, nil), do: Application.delete_env(:xturn, key)
  defp restore(key, value), do: Application.put_env(:xturn, key, value)
end
