defmodule Xirsys.XTurn.RFC5766Test do
  @moduledoc """
  RFC 5766 holes in the TURN *usage* (see RFC-8656). Codec coverage lives in
  xmedialib/test/rfc5766_test.exs. xsockets has no TURN state machine.
  """
  use ExUnit.Case, async: false
  import Bitwise

  alias XMediaLib.Stun
  alias XSockets.Config
  alias Xirsys.XTurn.{Conn, Pipeline, Tuple5}
  alias Xirsys.XTurn.Auth.Client, as: Auth
  alias Xirsys.XTurn.Allocate.{Client, Store}
  alias Xirsys.XTurn.TimedEntry

  @conn %Conn{
    client_ip: {127, 0, 0, 40},
    client_port: 9001,
    server_ip: {127, 0, 0, 1},
    server_port: 3478
  }

  @realm "xirsys.com"
  @udp <<17, 0, 0, 0>>
  @xor_peer_type 18
  @magic 0x2112A442

  describe "Allocate / Refresh (RFC 5766 / 8656 7.2 / 8.2)" do
    test "existing 5-tuple with a new transaction ID is 437 Allocation Mismatch" do
      conn = allocate_conn({127, 0, 0, 41}, 5_766_0101)
      first = Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0101)})
      assert first.response.class == :success

      second =
        Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0102)})

      assert second.response.err_no == 437
      refute second.response.class == :success
    end

    test "retransmitted Allocate with the same transaction ID is idempotent success" do
      conn = allocate_conn({127, 0, 0, 42}, 5_766_0103)
      stun = encode_allocate(5_766_0103)
      first = Pipeline.process_message(%Conn{conn | message: stun})
      assert first.response.class == :success
      {_, port} = first.response.attrs.xor_relayed_address

      second = Pipeline.process_message(%Conn{conn | message: stun})
      assert second.response.class == :success
      {_, ^port} = second.response.attrs.xor_relayed_address
    end

    test "Allocate echoes the client LIFETIME, capped at the server max of 600" do
      conn = allocate_conn({127, 0, 0, 43}, 5_766_0104)

      requested =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(5_766_0104, lifetime: <<120::32>>)
        })

      assert requested.response.class == :success
      assert requested.response.attrs.lifetime == <<120::32>>

      conn2 = allocate_conn({127, 0, 0, 44}, 5_766_0105)

      capped =
        Pipeline.process_message(%Conn{
          conn2
          | message: encode_allocate(5_766_0105, lifetime: <<9_000::32>>)
        })

      assert capped.response.class == :success
      assert capped.response.attrs.lifetime == <<600::32>>
    end

    test "Refresh without LIFETIME uses the default lifetime of 600" do
      conn = allocate_conn({127, 0, 0, 45}, 5_766_0106)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0106)}).response.class ==
               :success

      refreshed =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_request(:refresh, 5_766_0107, %{})
        })

      assert refreshed.response.class == :success
      assert refreshed.response.attrs.lifetime == <<600::32>>
    end

    test "EVEN-PORT R=1 returns a RESERVATION-TOKEN for port+1" do
      conn = allocate_conn({127, 0, 0, 47}, 5_766_0109)

      allocated =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(5_766_0109, even_port: <<0x80>>)
        })

      assert allocated.response.class == :success
      token = allocated.response.attrs.reservation_token
      assert is_binary(token)
      assert byte_size(token) == 8
      {_, port} = allocated.response.attrs.xor_relayed_address
      assert rem(port, 2) == 0

      reserved =
        Pipeline.process_message(%Conn{
          allocate_conn({127, 0, 0, 48}, 5_766_0110)
          | message: encode_allocate(5_766_0110, reservation_token: token)
        })

      assert reserved.response.class == :success
      {_, reserved_port} = reserved.response.attrs.xor_relayed_address
      assert reserved_port == port + 1
    end

    test "RESERVATION-TOKEN plus EVEN-PORT is 400" do
      conn = allocate_conn({127, 0, 0, 49}, 5_766_0111)

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_allocate(5_766_0111,
                even_port: <<0x80>>,
                reservation_token: <<1, 2, 3, 4, 5, 6, 7, 8>>
              )
        })

      assert result.response.err_no == 400
    end

    test "invalid RESERVATION-TOKEN is 508 Insufficient Capacity" do
      conn = allocate_conn({127, 0, 0, 50}, 5_766_0112)

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(5_766_0112, reservation_token: <<9, 9, 9, 9, 9, 9, 9, 9>>)
        })

      assert result.response.err_no == 508
    end
  end

  describe "auth and allocation identity (RFC 5766 / 8656 5 / 6)" do
    test "Refresh with a different username than Allocate is 441 Wrong Credentials" do
      {conn, nonce, realm} = authed_allocate({127, 0, 0, 51}, "rfc5766_a", "pass_a", 5_766_0201)
      Auth.add_user("rfc5766_b", "pass_b", "/", "server")
      key_b = :crypto.hash(:md5, "rfc5766_b:#{@realm}:pass_b")

      refresh =
        Stun.encode(%Stun{
          class: :request,
          method: :refresh,
          transactionid: 5_766_0202,
          fingerprint: false,
          integrity: true,
          key: key_b,
          attrs: %{
            username: "rfc5766_b",
            realm: realm,
            nonce: nonce,
            lifetime: <<300::32>>
          }
        })

      result = Pipeline.process_message(%Conn{conn | message: refresh, force_auth: true})
      assert result.response.err_no == 441
    end

    test "allocation stores the HMAC key: Refresh still works after the password in Auth.Client changes" do
      username = "rfc5766_key"
      password = "pass_original"
      {conn, nonce, realm} = authed_allocate({127, 0, 0, 52}, username, password, 5_766_0203)
      original_key = :crypto.hash(:md5, "#{username}:#{@realm}:#{password}")
      Auth.add_user(username, "pass_rotated", "/", "server")

      refresh =
        Stun.encode(%Stun{
          class: :request,
          method: :refresh,
          transactionid: 5_766_0204,
          fingerprint: false,
          integrity: true,
          key: original_key,
          attrs: %{
            username: username,
            realm: realm,
            nonce: nonce,
            lifetime: <<300::32>>
          }
        })

      result = Pipeline.process_message(%Conn{conn | message: refresh, force_auth: true})
      assert result.response.class == :success
    end

    test "CreatePermission with no allocation is 437" do
      conn = allocate_conn({127, 0, 0, 53}, 5_766_0205)

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:createperm, 5_766_0205, %{xor_peer_address: {{8, 8, 8, 8}, 3478}})
        })

      assert result.response.err_no == 437
    end

    test "ChannelBind with no allocation is 437" do
      conn = allocate_conn({127, 0, 0, 54}, 5_766_0206)

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:channelbind, 5_766_0206, %{
                channel_number: <<0x4000::16, 0::16>>,
                xor_peer_address: {{8, 8, 8, 8}, 3478}
              })
        })

      assert result.response.err_no == 437
    end
  end

  describe "permissions and channels (RFC 5766 / 8656 9 / 10 / 12)" do
    test "ChannelBind installs a permission for the peer IP" do
      conn = allocate_conn({127, 0, 0, 55}, 5_766_0301)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0301)}).response.class ==
               :success

      peer_ip = {8, 8, 4, 4}

      bound =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:channelbind, 5_766_0302, %{
                channel_number: <<0x4000::16, 0::16>>,
                xor_peer_address: {peer_ip, 3478}
              })
        })

      assert bound.response.class == :success
      tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))
      {:ok, [client, _, _, _]} = Store.lookup(tuple5)
      {:ok, perms} = Client.get_permission_cache(client)
      assert wait_until(fn -> TimedEntry.has_key?(perms, peer_ip) end)
    end

    test "CreatePermission installs a permission per XOR-PEER-ADDRESS" do
      conn = allocate_conn({127, 0, 0, 56}, 5_766_0303)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0303)}).response.class ==
               :success

      peer_a = {{8, 8, 8, 8}, 3478}
      peer_b = {{1, 1, 1, 1}, 3479}

      permed =
        Pipeline.process_message(%Conn{
          conn
          | message: createperm_with_peers(5_766_0304, [peer_a, peer_b])
        })

      assert permed.response.class == :success
      tuple5 = Tuple5.to_map(Tuple5.create(conn, :_))
      {:ok, [client, _, _, _]} = Store.lookup(tuple5)
      {:ok, perms} = Client.get_permission_cache(client)
      assert wait_until(fn -> TimedEntry.has_key?(perms, elem(peer_a, 0)) end)
      assert wait_until(fn -> TimedEntry.has_key?(perms, elem(peer_b, 0)) end)
    end

    test "CreatePermission toward the server's own address is 403 Forbidden" do
      conn = allocate_conn({127, 0, 0, 57}, 5_766_0305)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0305)}).response.class ==
               :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:createperm, 5_766_0306, %{
                xor_peer_address: {Config.server_ip(), 3478}
              })
        })

      assert result.response.err_no == 403
    end

    test "CreatePermission toward another relay port on server_ip is allowed (hairpin)" do
      server_ip = Config.server_ip()

      for {client_ip, tid} <- [
            {{127, 0, 0, 62}, 5_766_0310},
            {server_ip, 5_766_0312}
          ] do
        conn = allocate_conn(client_ip, tid)
        assert Pipeline.process_message(%Conn{conn | message: encode_allocate(tid)}).response.class ==
                 :success

        result =
          Pipeline.process_message(%Conn{
            conn
            | message:
                encode_request(:createperm, tid + 1, %{
                  xor_peer_address: {server_ip, 54_149}
                })
          })

        assert result.response.class == :success
      end
    end

    test "CreatePermission toward broadcast is 403 Forbidden" do
      conn = allocate_conn({127, 0, 0, 58}, 5_766_0307)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0307)}).response.class ==
               :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:createperm, 5_766_0308, %{
                xor_peer_address: {{255, 255, 255, 255}, 3478}
              })
        })

      assert result.response.err_no == 403
    end
  end

  describe "Send / ChannelData (RFC 5766 / 8656 11 / 12.6)" do
    test "Send indication missing DATA or XOR-PEER-ADDRESS is silently dropped" do
      conn = allocate_conn({127, 0, 0, 59}, 5_766_0401)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0401)}).response.class ==
               :success

      no_data =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_indication(:send, 5_766_0402, %{xor_peer_address: {{8, 8, 8, 8}, 3478}})
        })

      no_peer =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_indication(:send, 5_766_0403, %{data: "ping"})
        })

      assert no_data == false or (is_struct(no_data, Conn) and no_data.response == nil)
      assert no_peer == false or (is_struct(no_peer, Conn) and no_peer.response == nil)
    end

    test "Send indication with no permission is silently dropped" do
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, peer_port} = :inet.port(peer)

      conn = allocate_conn({127, 0, 0, 60}, 5_766_0404)
      allocated = Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0404)})
      assert allocated.response.class == :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_indication(:send, 5_766_0405, %{
                xor_peer_address: {{127, 0, 0, 1}, peer_port},
                data: "nope"
              })
        })

      assert is_struct(result, Conn)
      assert result.response == nil
      assert {:error, :timeout} = :gen_udp.recv(peer, 0, 200)
      :gen_udp.close(peer)
    end

    test "ChannelData on an unbound channel is silently dropped" do
      conn = allocate_conn({127, 0, 0, 61}, 5_766_0406)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(5_766_0406)}).response.class ==
               :success

      assert Pipeline.process_message(%Conn{conn | message: <<0x4000::16, 4::16, "ping">>}) ==
               false
    end
  end

  defp allocate_conn(client_ip, _tid) do
    %Conn{
      @conn
      | client_ip: client_ip,
        client_socket: fake_client_socket()
    }
  end

  defp authed_allocate(client_ip, username, password, tid) do
    Auth.add_user(username, password, "/", "server")
    conn = %Conn{allocate_conn(client_ip, tid) | force_auth: true}
    base = allocation_struct(tid)

    challenge =
      Pipeline.process_message(%Conn{
        conn
        | message: Stun.encode(struct(base, attrs: Map.put(base.attrs, :username, username)))
      })

    nonce = Map.get(challenge.decoded_message.attrs, :nonce)
    realm = Map.get(challenge.decoded_message.attrs, :realm)
    key = :crypto.hash(:md5, "#{username}:#{@realm}:#{password}")

    authed =
      Stun.encode(%Stun{
        class: :request,
        method: :allocate,
        transactionid: tid,
        fingerprint: false,
        integrity: true,
        key: key,
        attrs:
          base.attrs
          |> Map.put(:username, username)
          |> Map.put(:realm, realm)
          |> Map.put(:nonce, nonce)
      })

    allocated = Pipeline.process_message(%Conn{conn | message: authed})
    assert allocated.response.class == :success
    {conn, nonce, realm}
  end

  defp encode_allocate(tid, extra \\ []) do
    attrs =
      extra
      |> Enum.into(%{})
      |> Map.put(:requested_transport, @udp)

    Stun.encode(%Stun{
      class: :request,
      method: :allocate,
      transactionid: tid,
      fingerprint: false,
      attrs: attrs
    })
  end

  defp encode_request(method, tid, attrs) do
    Stun.encode(%Stun{
      class: :request,
      method: method,
      transactionid: tid,
      fingerprint: false,
      attrs: attrs
    })
  end

  defp encode_indication(method, tid, attrs) do
    Stun.encode(%Stun{
      class: :indication,
      method: method,
      transactionid: tid,
      fingerprint: false,
      attrs: attrs
    })
  end

  defp allocation_struct(tid) do
    %Stun{
      class: :request,
      method: :allocate,
      transactionid: tid,
      attrs: %{requested_transport: @udp}
    }
  end

  defp createperm_with_peers(tid, [first | rest]) do
    bin = encode_request(:createperm, tid, %{xor_peer_address: first})

    Enum.reduce(rest, bin, fn peer, acc ->
      <<type::16, len::16, cookie::32, tid_bin::96, attrs::binary>> = acc
      tlv = xor_peer_tlv(peer)
      <<type::16, len + byte_size(tlv)::16, cookie::32, tid_bin::96, attrs::binary, tlv::binary>>
    end)
  end

  defp xor_peer_tlv({{i0, i1, i2, i3}, port}) do
    xport = bxor(port, bsr(@magic, 16))
    <<addr::32>> = <<i0, i1, i2, i3>>
    xaddr = bxor(addr, @magic)
    value = <<0, 1, xport::16, xaddr::32>>
    <<@xor_peer_type::16, byte_size(value)::16, value::binary>>
  end

  defp fake_client_socket do
    Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, :fake, {127, 0, 0, 1}, 9999)
  end

  defp wait_until(fun, attempts \\ 50)

  defp wait_until(_fun, 0), do: false

  defp wait_until(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(10)
      wait_until(fun, attempts - 1)
    end
  end
end
