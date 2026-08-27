defmodule StunTest do
  use ExUnit.Case

  alias XMediaLib.Stun
  alias Xirsys.XTurn.{Conn, Pipeline}

  @conn %Conn{
    client_ip: {127, 0, 0, 2},
    client_port: 8881,
    server_ip: {127, 0, 0, 3},
    server_port: 8882
  }

  setup do
    stun_msg =
      struct(Stun, %{
        class: :request,
        method: :binding,
        transactionid: 123_456_789_012
      })

    {:ok, stun: Stun.encode(stun_msg)}
  end

  test "valid stun packet format", %{stun: stun} do
    assert valid_stun(stun)
  end

  test "returns valid response", %{stun: stun} do
    conn = Pipeline.process_message(%Conn{@conn | message: stun})

    assert conn.response.class == :success,
           "STUN request should be valid"

    assert Map.get(conn.response.attrs || %{}, :xor_mapped_address) ==
             {@conn.client_ip, @conn.client_port},
           "must return a xor-mapped-address"

    assert Map.get(conn.response.attrs || %{}, :mapped_address) ==
             {@conn.client_ip, @conn.client_port},
           "must return a mapped-address"

    assert Map.get(conn.response.attrs || %{}, :response_origin) ==
             {@conn.server_ip, @conn.server_port},
           "must return a response-origin"
  end

  defp valid_stun(<<0::2, _::14, _rest::binary>>) do
    true
  end

  defp valid_stun(_), do: false

  describe "decoding a Send/Data Indication wrapping a fingerprinted inner STUN message" do
    test "does not truncate the DATA attribute's value" do
      inner_stun =
        struct(Stun, %{
          class: :request,
          method: :binding,
          transactionid: 111_222_333_444,
          fingerprint: true,
          attrs: %{username: "checker"}
        })

      inner_bytes = Stun.encode(inner_stun)
      # Sanity check: the inner message genuinely ends in its own FINGERPRINT, which
      # is what triggers the bug if the outer decode isn't attribute-aware.
      assert :binary.match(inner_bytes, <<0x80, 0x28, 0x00, 0x04>>) != :nomatch

      outer_stun =
        struct(Stun, %{
          class: :indication,
          method: :send,
          transactionid: 555_666_777_888,
          fingerprint: false,
          attrs: %{data: inner_bytes}
        })

      outer_bytes = Stun.encode(outer_stun)

      assert {:ok, decoded} = Stun.decode(outer_bytes)

      assert Map.get(decoded.attrs, :data) == inner_bytes,
             "the wrapped inner message must be relayed byte-for-byte, without truncation"
    end

    test "still strips a genuine top-level FINGERPRINT" do
      stun = struct(Stun, %{class: :request, method: :binding, transactionid: 1, fingerprint: true})
      encoded = Stun.encode(stun)

      assert {:ok, decoded} = Stun.decode(encoded)
      assert decoded.class == :request
      assert decoded.method == :binding
    end
  end
end
