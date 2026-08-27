defmodule Xirsys.XTurn.RFC5780Test do
  @moduledoc """
  RFC 5780 NAT Behavior Discovery on Binding (see RFC-5780).
  """
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias XSockets.Transport.UDP
  alias Xirsys.XTurn.{Conn, ListenRegistry, Pipeline}

  @a1 {127, 0, 0, 1}
  @a2 {127, 0, 0, 2}
  @p1 5781
  @p2 5782

  @conn %Conn{
    client_ip: {127, 0, 0, 50},
    client_port: 9001,
    server_ip: @a1,
    server_port: @p1,
    client_socket: nil
  }

  setup do
    ListenRegistry.ensure!()

    saved = %{
      other_ip: Application.get_env(:xturn, :other_ip),
      other_port: Application.get_env(:xturn, :other_port),
      stun_port: Application.get_env(:xturn, :stun_port),
      server_ip: Application.get_env(:xturn, :server_ip)
    }

    on_exit(fn ->
      restore_env(:other_ip, saved.other_ip)
      restore_env(:other_port, saved.other_port)
      restore_env(:stun_port, saved.stun_port)
      Application.put_env(:xturn, :server_ip, saved.server_ip)

      for {ip, port} <- [{@a1, @p1}, {@a2, @p2}, {@a1, @p2}, {@a2, @p1}] do
        Process.delete({:rfc5780_sock, ip, port})
      end
    end)

    {:ok, saved: saved}
  end

  describe "unarmed (no dual UDP endpoints)" do
    test "ICE Binding succeeds without OTHER-ADDRESS" do
      conn = process_binding(%{})
      assert conn.response.class == :success
      refute Map.has_key?(conn.response.attrs, :other_address)
    end

    test "CHANGE-REQUEST returns 420 when dual-IP is not armed" do
      conn = Pipeline.process_message(udp_conn(encode_binding(attrs: %{change_request: [:port]})))
      assert conn.response.err_no == 420
    end
  end

  describe "armed dual-IP" do
    setup %{saved: _saved} do
      {:ok, sockets: arm_dual!()}
    end

    test "Binding includes OTHER-ADDRESS", %{sockets: _} do
      conn = process_binding(%{})
      assert conn.response.attrs.other_address == {@a2, @p2}
      assert conn.response.attrs.response_origin == {@a1, @p1}
    end

    test "ICE Binding without 5780 attrs still succeeds with OTHER-ADDRESS", %{sockets: _} do
      conn = process_binding(%{})
      assert conn.response.class == :success
      assert conn.response.attrs.xor_mapped_address == {@conn.client_ip, @conn.client_port}
    end

    test "CHANGE-REQUEST change-port replies from the crossed local endpoint", %{sockets: _} do
      conn =
        Pipeline.process_message(
          udp_conn(encode_binding(attrs: %{change_request: [:port]}))
        )

      assert conn.response.class == :success
      assert conn.reply_from == {UDP, socket_for(@a1, @p2)}
      assert conn.reply_to == {@conn.client_ip, @conn.client_port}
      assert conn.response.attrs.response_origin == {@a1, @p2}
    end

    test "RESPONSE-PORT sends to the requested client port", %{sockets: _} do
      conn =
        Pipeline.process_message(
          udp_conn(encode_binding(attrs: %{response_port: <<12_345::16, 0::16>>}))
        )

      assert conn.response.class == :success
      assert conn.reply_to == {@conn.client_ip, 12_345}
    end

    test "RESPONSE-PORT and PADDING together is 400", %{sockets: _} do
      conn =
        Pipeline.process_message(
          udp_conn(
            encode_binding(attrs: %{
              response_port: <<12_345::16, 0::16>>,
              padding: <<"pad">>
            })
          )
        )

      assert conn.response.err_no == 400
    end

    test "CHANGE-REQUEST on TCP returns 420", %{sockets: _} do
      conn =
        Pipeline.process_message(%Conn{
          udp_conn(encode_binding(attrs: %{change_request: [:port]}))
          | client_socket:
              Xirsys.XTurn.ClientSocket.new(
                XSockets.Transport.TCP,
                :fake,
                @conn.client_ip,
                @conn.client_port
              )
        })

      assert conn.response.err_no == 420
    end
  end

  defp arm_dual!() do
    Application.put_env(:xturn, :other_ip, @a2)
    Application.put_env(:xturn, :other_port, @p2)
    Application.put_env(:xturn, :stun_port, @p1)
    Application.put_env(:xturn, :server_ip, @a1)

    for {ip, port} <- [{@a1, @p1}, {@a2, @p2}, {@a1, @p2}, {@a2, @p1}] do
      fake = {:fake, ip, port}
      :ok = ListenRegistry.register({ip, port}, {UDP, fake})
      Process.put({:rfc5780_sock, ip, port}, fake)
      {ip, port, fake}
    end
  end

  defp socket_for(ip, port) do
    Process.get({:rfc5780_sock, ip, port}) ||
      raise "socket not registered for #{inspect(ip)}:#{port}"
  end

  defp process_binding(attrs) do
    Pipeline.process_message(udp_conn(encode_binding(attrs: attrs)))
  end

  defp udp_conn(stun) do
    %Conn{
      @conn
      | message: stun,
        client_socket:
          Xirsys.XTurn.ClientSocket.new(UDP, :fake, @conn.client_ip, @conn.client_port)
    }
  end

  defp encode_binding(opts \\ []) do
    Stun.encode(%Stun{
      class: Keyword.get(opts, :class, :request),
      method: :binding,
      transactionid: Keyword.get(opts, :transactionid, 5_780_001),
      fingerprint: false,
      attrs: Keyword.get(opts, :attrs, %{})
    })
  end

  defp restore_env(key, nil), do: Application.delete_env(:xturn, key)
  defp restore_env(key, val), do: Application.put_env(:xturn, key, val)
end
