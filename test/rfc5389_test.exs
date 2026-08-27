defmodule Xirsys.XTurn.RFC5389Test do
  @moduledoc """
  RFC 5389 holes in the TURN/STUN *usage* (see RFC-8489). Codec coverage lives
  in xmedialib/test/rfc5389_test.exs. xsockets has no STUN semantics.
  """
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias Xirsys.XTurn.{Conn, Pipeline}
  alias Xirsys.XTurn.Auth.Client, as: Auth
  alias Xirsys.XTurn.Allocate.Client, as: AllocateClient

  @conn %Conn{
    client_ip: {127, 0, 0, 21},
    client_port: 9001,
    server_ip: {127, 0, 0, 1},
    server_port: 3478
  }

  @realm "xirsys.com"
  @unknown_required 0x1234
  @unknown_optional 0x8055

  describe "unknown comprehension-required attributes (RFC 5389 6.3.1)" do
    test "Binding with an unknown required attr replies 420 and does not succeed" do
      stun = encode_binding(attrs: %{@unknown_required => <<0, 0, 0, 0>>})
      conn = Pipeline.process_message(%Conn{@conn | message: stun})

      assert conn.response.err_no == 420
      ua = Map.get(conn.decoded_message.attrs, :unknown_attributes)
      assert is_binary(ua)
      assert :binary.match(ua, <<@unknown_required::16>>) != :nomatch
      refute conn.response.class == :success
      refute Map.has_key?(conn.decoded_message.attrs, :realm)
      refute Map.has_key?(conn.decoded_message.attrs, :nonce)
    end

    test "Binding with an unknown optional attr still succeeds" do
      stun = encode_binding(attrs: %{@unknown_optional => <<0, 0, 0, 0>>})
      conn = Pipeline.process_message(%Conn{@conn | message: stun})
      assert conn.response.class == :success
    end
  end

  describe "long-term credential checks (RFC 5389 10.2)" do
    test "MESSAGE-INTEGRITY without USERNAME, REALM, or NONCE is 400 without a challenge" do
      key = :crypto.hash(:md5, "nobody:#{@realm}:nopass")
      base = allocation_request()

      stun =
        Stun.encode(%Stun{
          class: :request,
          method: :allocate,
          transactionid: base.transactionid,
          fingerprint: false,
          integrity: true,
          key: key,
          attrs: Map.put(base.attrs, :requested_transport, <<17, 0, 0, 0>>)
        })

      conn =
        Pipeline.process_message(%Conn{
          @conn
          | message: stun,
            client_ip: {127, 0, 0, 22},
            force_auth: true,
            client_socket: fake_client_socket()
        })

      assert conn.response.err_no == 400
      attrs = conn.decoded_message.attrs
      refute Map.has_key?(attrs, :realm)
      refute Map.has_key?(attrs, :nonce)
    end

    test "HMAC mismatch with complete credentials is 401 with REALM and NONCE" do
      client_ip = {127, 0, 0, 23}
      username = "rfc5389_hmac_user"
      password = "rfc5389_hmac_pass"
      Auth.add_user(username, password, "/", "server")
      base = allocation_request()

      challenge =
        Pipeline.process_message(%Conn{
          @conn
          | message: Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, username))),
            client_ip: client_ip,
            force_auth: true,
            client_socket: fake_client_socket()
        })

      nonce = Map.get(challenge.decoded_message.attrs, :nonce)
      realm = Map.get(challenge.decoded_message.attrs, :realm)
      wrong_key = :crypto.hash(:md5, username <> ":" <> @realm <> ":wrong")

      stun =
        Stun.encode(%Stun{
          class: :request,
          method: :allocate,
          transactionid: 5389_0002,
          fingerprint: false,
          integrity: true,
          key: wrong_key,
          attrs:
            base.attrs
            |> Map.put(:username, username)
            |> Map.put(:realm, realm)
            |> Map.put(:nonce, nonce)
        })

      {:ok, orig_workers} = AllocateClient.count()

      conn =
        Pipeline.process_message(%Conn{
          @conn
          | message: stun,
            client_ip: client_ip,
            force_auth: true,
            client_socket: fake_client_socket()
        })

      assert conn.response.err_no == 401
      assert Map.get(conn.decoded_message.attrs, :realm) == @realm
      assert is_binary(Map.get(conn.decoded_message.attrs, :nonce))
      assert AllocateClient.count() == {:ok, orig_workers}
    end
  end

  describe "silent discard (RFC 5389 6)" do
    test "Binding indication produces no response" do
      stun = encode_binding(class: :indication)
      conn = Pipeline.process_message(%Conn{@conn | message: stun})
      assert %Conn{} = conn
      assert conn.response == nil
    end

    test "Binding indication with unknown required attr is silently discarded, not 420" do
      stun = encode_binding(class: :indication, attrs: %{@unknown_required => <<0, 0, 0, 0>>})
      conn = Pipeline.process_message(%Conn{@conn | message: stun})
      assert %Conn{} = conn
      assert conn.response == nil
    end

    test "unknown method produces no response" do
      stun = encode_binding(method: 0x050)
      conn = Pipeline.process_message(%Conn{@conn | message: stun})
      assert %Conn{} = conn
      assert conn.response == nil
    end

    test "Binding success sent to the server produces no response" do
      stun = encode_binding(class: :success)
      conn = Pipeline.process_message(%Conn{@conn | message: stun})
      assert %Conn{} = conn
      assert conn.response == nil
    end

    test "wrong magic cookie is dropped, not a raise" do
      <<type::16, len::16, _cookie::32, rest::binary>> = encode_binding()
      bad = <<type::16, len::16, 0xDEADBEEF::32, rest::binary>>

      assert Pipeline.process_message(%Conn{@conn | message: bad}) == false
    end

    test "forged FINGERPRINT is dropped, not processed as Binding" do
      bin = encode_binding(fingerprint: true)
      corrupted = :binary.part(bin, 0, byte_size(bin) - 1) <> <<Bitwise.bxor(:binary.last(bin), 1)>>
      assert Pipeline.process_message(%Conn{@conn | message: corrupted}) == false
    end
  end

  defp encode_binding(opts \\ []) do
    Stun.encode(%Stun{
      class: Keyword.get(opts, :class, :request),
      method: Keyword.get(opts, :method, :binding),
      transactionid: Keyword.get(opts, :transactionid, 5389),
      fingerprint: Keyword.get(opts, :fingerprint, false),
      attrs: Keyword.get(opts, :attrs, %{})
    })
  end

  defp allocation_request do
    %Stun{
      class: :request,
      method: :allocate,
      transactionid: 5_389_0001,
      attrs: %{requested_transport: <<17, 0, 0, 0>>}
    }
  end

  defp fake_client_socket do
    Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, :fake, {127, 0, 0, 1}, 9999)
  end
end
