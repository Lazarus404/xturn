defmodule Xirsys.XTurn.RFC3489Test do
  @moduledoc """
  RFC 3489 pt.12.2 cookie-less Binding interop (not classic NAT discovery).
  """
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias XSockets.Transport.{TLS, UDP}
  alias Xirsys.XTurn.{Conn, Pipeline}

  @conn %Conn{
    client_ip: {127, 0, 0, 60},
    client_port: 9001,
    server_ip: {127, 0, 0, 1},
    server_port: 3478,
    client_socket: nil
  }

  @classic_cookie 0xDEADBEEF

  setup do
    saved = Application.get_env(:xturn, :rfc3489_compat)

    on_exit(fn ->
      if is_nil(saved) do
        Application.delete_env(:xturn, :rfc3489_compat)
      else
        Application.put_env(:xturn, :rfc3489_compat, saved)
      end
    end)

    :ok
  end

  test "cookie-less Binding is dropped when rfc3489_compat is off" do
    Application.put_env(:xturn, :rfc3489_compat, false)
    assert Pipeline.process_message(udp_conn(classic_binding())) == false
  end

  test "cookie-less Binding returns MAPPED-ADDRESS when compat is on" do
    Application.put_env(:xturn, :rfc3489_compat, true)
    conn = Pipeline.process_message(udp_conn(classic_binding()))

    assert conn.response.class == :success
    assert conn.response.attrs.mapped_address == {@conn.client_ip, @conn.client_port}
    refute Map.has_key?(conn.response.attrs, :xor_mapped_address)

    {:ok, encoded} = Conn.to_reply(conn)
    <<_::16, _::16, @classic_cookie::32, _::binary>> = encoded
  end

  test "CHANGE-REQUEST on a classic Binding is 420" do
    Application.put_env(:xturn, :rfc3489_compat, true)

    stun =
      Stun.encode(%Stun{
        class: :request,
        method: :binding,
        transactionid: 3_489_002,
        classic: true,
        classic_cookie: @classic_cookie,
        fingerprint: false,
        attrs: %{change_request: [:port]}
      })

    conn = Pipeline.process_message(udp_conn(stun))
    assert conn.response.err_no == 420
  end

  test "cookie-less Binding is not accepted on non-UDP transports" do
    Application.put_env(:xturn, :rfc3489_compat, true)

    conn = %Conn{
      udp_conn(classic_binding())
      | client_socket: Xirsys.XTurn.ClientSocket.new(TLS, :fake, @conn.client_ip, @conn.client_port)
    }

    assert Pipeline.process_message(conn) == false
  end

  test "nil rfc3489_compat is treated as off" do
    Application.put_env(:xturn, :rfc3489_compat, nil)
    assert Pipeline.process_message(udp_conn(classic_binding())) == false
  end

  defp classic_binding() do
    Stun.encode(%Stun{
      class: :request,
      method: :binding,
      transactionid: 3_489_001,
      classic: true,
      classic_cookie: @classic_cookie,
      fingerprint: false,
      attrs: %{}
    })
  end

  defp udp_conn(message) do
    %Conn{
      @conn
      | message: message,
        client_socket:
          Xirsys.XTurn.ClientSocket.new(UDP, :fake, @conn.client_ip, @conn.client_port)
    }
  end
end
