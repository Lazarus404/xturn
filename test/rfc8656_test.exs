defmodule Xirsys.XTurn.RFC8656Test do
  @moduledoc """
  RFC 8656 TURN *usage* holes (see RFC-8656). Codec coverage lives in
  xmedialib/test/stun_turn/rfc8656_test.exs. xsockets has no TURN state machine.

  Skipped here: RFC 7635, packet translation / PMTUD (needs dual-stack relay),
  ICMP Data indication (needs sockets error-queue), client URI/DNS/Happy Eyeballs.
  """
  use ExUnit.Case, async: false

  alias XSockets.Transport.{DTLS, TCP, TLS, UDP}
  alias XMediaLib.Stun
  alias Xirsys.XTurn.{Conn, Pipeline}
  alias Xirsys.XTurn.Auth.Client, as: Auth

  @conn %Conn{
    client_ip: {127, 0, 0, 100},
    client_port: 9001,
    server_ip: {127, 0, 0, 1},
    server_port: 3478
  }

  @udp <<17, 0, 0, 0>>
  @ipv4 <<0x01, 0, 0, 0>>
  @ipv6 <<0x02, 0, 0, 0>>
  @additional_type 0x8000
  @peer_v6 {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 3478}

  describe "486 Allocation Quota Reached (RFC 8656 7.2 check 10)" do
    test "second Allocate for the same username is 486 when quota is 1" do
      username = "rfc8656_quota"
      password = "rfc8656_quota_pass"
      Auth.add_user(username, password, "/", "server")

      old = Application.get_env(:xturn, :allocation_quota)
      Application.put_env(:xturn, :allocation_quota, 1)
      on_exit(fn -> restore_env(:xturn, :allocation_quota, old) end)

      first = authed_allocate({127, 0, 0, 101}, username, password, 8_656_0101)
      assert first.response.class == :success

      second = authed_allocate({127, 0, 0, 102}, username, password, 8_656_0102)
      assert second.response.err_no == 486
    end
  end

  describe "REQUESTED-ADDRESS-FAMILY (RFC 8656 7.2 / 18.6)" do
    test "absent or IPv4 allocates an IPv4 relay" do
      conn = allocate_conn({127, 0, 0, 103})
      result = Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0201)})
      assert result.response.class == :success
      {ip, _port} = relay_addr(result)
      assert tuple_size(ip) == 4

      conn2 = allocate_conn({127, 0, 0, 104})

      v4 =
        Pipeline.process_message(%Conn{
          conn2
          | message: encode_allocate(8_656_0202, requested_address_type: @ipv4)
        })

      assert v4.response.class == :success
      {ip4, _} = relay_addr(v4)
      assert tuple_size(ip4) == 4
    end

    test "unsupported family is 440 Address Family not Supported" do
      conn = allocate_conn({127, 0, 0, 105})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_656_0203, requested_address_type: @ipv6)
        })

      # Until an IPv6 relay exists, IPv6 MUST be 440 - not a silent IPv4 allocate.
      if result.response.class == :success do
        {ip, _} = relay_addr(result)
        assert tuple_size(ip) == 8
      else
        assert result.response.err_no == 440
      end
    end
  end

  describe "ADDITIONAL-ADDRESS-FAMILY (RFC 8656 7.2 checks 5–9)" do
    test "REQUESTED-ADDRESS-FAMILY plus ADDITIONAL-ADDRESS-FAMILY is 400" do
      conn = allocate_conn({127, 0, 0, 106})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_allocate(8_656_0301,
                requested_address_type: @ipv4,
                additional: @ipv6
              )
        })

      assert result.response.err_no == 400
    end

    test "ADDITIONAL-ADDRESS-FAMILY 0x01 (IPv4) is 400" do
      conn = allocate_conn({127, 0, 0, 107})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_656_0302, additional: @ipv4)
        })

      assert result.response.err_no == 400
    end

    test "EVEN-PORT R=1 plus ADDITIONAL-ADDRESS-FAMILY is 400" do
      conn = allocate_conn({127, 0, 0, 108})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_656_0303, even_port: <<0x80>>, additional: @ipv6)
        })

      assert result.response.err_no == 400
    end

    test "RESERVATION-TOKEN plus ADDITIONAL-ADDRESS-FAMILY is 400" do
      conn = allocate_conn({127, 0, 0, 109})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_allocate(8_656_0304,
                reservation_token: <<1, 2, 3, 4, 5, 6, 7, 8>>,
                additional: @ipv6
              )
        })

      assert result.response.err_no == 400
    end

    test "ADDITIONAL-ADDRESS-FAMILY 0x02 is dual success, partial plus ADDRESS-ERROR-CODE, or 508" do
      conn = allocate_conn({127, 0, 0, 110})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_656_0305, additional: @ipv6)
        })

      # 7.2 check 9: both families, one family + ADDRESS-ERROR-CODE, or 508.
      # Silent IPv4-only success (today) is not any of those.
      cond do
        result.response.err_no == 508 ->
          :ok

        result.response.class == :success ->
          relays = List.wrap(result.response.attrs.xor_relayed_address)
          families = relays |> Enum.map(&elem(&1, 0)) |> Enum.map(&tuple_size/1) |> Enum.sort()
          attrs = result.response.attrs

          cond do
            families == [4, 8] ->
              :ok

            families in [[4], [8]] and Map.has_key?(attrs, :address_error_code) ->
              :ok

            true ->
              flunk(
                "dual Allocate must be v4+v6, partial+ADDRESS-ERROR-CODE, or 508, got families=#{inspect(families)} attrs=#{inspect(Map.keys(attrs))}"
              )
          end

        true ->
          flunk("dual Allocate expected success or 508, got #{inspect(result.response)}")
      end
    end
  end

  describe "443 Peer Address Family Mismatch (RFC 8656 10.2 / 12.2 / 8.2)" do
    test "CreatePermission with an IPv6 peer on an IPv4 allocation is 443" do
      conn = allocate_conn({127, 0, 0, 111})
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0401)}).response.class ==
               :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_request(:createperm, 8_656_0402, %{xor_peer_address: @peer_v6})
        })

      assert result.response.err_no == 443
    end

    test "ChannelBind with an IPv6 peer on an IPv4 allocation is 443" do
      conn = allocate_conn({127, 0, 0, 112})
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0403)}).response.class ==
               :success

      result =
        try do
          Pipeline.process_message(%Conn{
            conn
            | message:
                encode_request(:channelbind, 8_656_0404, %{
                  channel_number: <<0x4000::16, 0::16>>,
                  xor_peer_address: @peer_v6
                })
          })
        catch
          :exit, reason ->
            flunk("expected 443, allocation process exited: #{inspect(reason)}")
        end

      assert result.response.err_no == 443
    end

    test "Refresh REQUESTED-ADDRESS-FAMILY that does not match the allocation is 443" do
      conn = allocate_conn({127, 0, 0, 113})
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0405)}).response.class ==
               :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_request(:refresh, 8_656_0406, %{requested_address_type: @ipv6})
        })

      assert result.response.err_no == 443
    end
  end

  describe "peer filter (RFC 8656 10.2 MAY / 21.4)" do
    test "CreatePermission toward the client's own address is 403" do
      client_ip = {203, 0, 113, 50}
      conn = allocate_conn(client_ip)
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0501)}).response.class ==
               :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:createperm, 8_656_0502, %{xor_peer_address: {client_ip, 3478}})
        })

      assert result.response.err_no == 403
    end

    test "Teredo or 6to4 peer on an IPv4 allocation is 443 (family mismatch before 21.4)" do
      conn = allocate_conn({127, 0, 0, 114})
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0503)}).response.class ==
               :success

      teredo = {{0x2001, 0, 0, 0, 0, 0, 0, 1}, 3478}
      sixto4 = {{0x2002, 0, 0, 0, 0, 0, 0, 1}, 3478}

      for {tid, peer} <- [{8_656_0504, teredo}, {8_656_0506, sixto4}] do
        result =
          Pipeline.process_message(%Conn{
            conn
            | message: encode_request(:createperm, tid, %{xor_peer_address: peer})
          })

        assert result.response.err_no == 443
      end
    end
  end

  describe "ICMP Data indication (RFC 8656 15)" do
    test "icmp_indication encodes ICMP attribute toward the client" do
      bin = Xirsys.XTurn.StunHelper.icmp_indication({{8, 8, 8, 8}, 3478}, 3, 4, 1280)
      assert {:ok, decoded} = Stun.decode(bin)
      assert decoded.attrs.icmp == <<0::16, 3::8, 4::8, 1280::32>>
      assert decoded.method == :data
      assert decoded.class == :indication
    end
  end

  @tcp <<6, 0, 0, 0>>

  describe "RFC 6062 / RFC 7350 TCP allocation transport (442)" do
    test "TCP REQUESTED-TRANSPORT on UDP control is 442" do
      conn = allocate_conn({127, 0, 0, 119})

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_656_0701, requested_transport: @tcp)
        })

      assert result.response.err_no == 442
    end

    test "TCP REQUESTED-TRANSPORT on DTLS control is 442" do
      conn =
        %Conn{
          allocate_conn({127, 0, 0, 120})
          | client_socket: fake_client_socket(DTLS)
        }

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_656_0702, requested_transport: @tcp)
        })

      assert result.response.err_no == 442
    end
  end

  describe "RFC 6062 TCP relay (RFC 8656 5 SHOULD)" do
    test "Connect on a UDP allocation is 437 Allocation Mismatch" do
      conn = allocate_conn({127, 0, 0, 116})
      assert Pipeline.process_message(%Conn{conn | message: encode_allocate(8_656_0601)}).response.class ==
               :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_request(:connect, 8_656_0602, %{xor_peer_address: {{8, 8, 8, 8}, 80}})
        })

      assert result.response.err_no == 437
    end

    test "TCP allocate Connect returns connection_id and ConnectionBind succeeds" do
      loopback = {127, 0, 0, 1}
      client_ip = {127, 0, 0, 117}
      test_pid = self()

      {:ok, peer_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: loopback])
      {:ok, {_, peer_port}} = :inet.sockname(peer_listen)

      spawn(fn ->
        case :gen_tcp.accept(peer_listen, 5_000) do
          {:ok, peer_sock} ->
            _ = :gen_tcp.controlling_process(peer_sock, test_pid)
            send(test_pid, {:peer_sock, peer_sock})

          {:error, reason} ->
            send(test_pid, {:peer_accept_error, reason})
        end
      end)

      on_exit(fn ->
        if is_port(peer_listen), do: :gen_tcp.close(peer_listen)
      end)

      conn = tcp_allocate_conn(client_ip)

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   Stun.encode(%Stun{
                     class: :request,
                     method: :allocate,
                     transactionid: 8_656_0603,
                     fingerprint: false,
                     attrs: %{requested_transport: <<6, 0, 0, 0>>}
                   })
             }).response.class == :success

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:createperm, 8_656_0604, %{
                     xor_peer_address: {loopback, peer_port}
                   })
             }).response.class == :success

      connect_result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:connect, 8_656_0605, %{xor_peer_address: {loopback, peer_port}})
        })

      assert connect_result.response.class == :success
      connection_id = Map.fetch!(connect_result.response.attrs, :connection_id)
      assert is_binary(connection_id) and byte_size(connection_id) == 4

      assert_receive {:peer_sock, peer_sock}, 5_000
      assert is_port(peer_sock)

      assert {:ok, _} = Xirsys.XTurn.Allocate.TcpRegistry.lookup_alloc(connection_id)

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:connection_bind, 8_656_0606, %{
                     connection_id: connection_id
                   })
             }).response.class == :success

      :gen_tcp.close(peer_sock)
    end

    test "ConnectionBind success carries MESSAGE-INTEGRITY on a new TCP 5-tuple" do
      loopback = {127, 0, 0, 1}
      client_ip = {127, 0, 0, 118}
      username = "rfc6062_bind"
      password = "rfc6062_bind_pass"
      Auth.add_user(username, password, "/", "server")

      {:ok, peer_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: loopback])
      {:ok, {_, peer_port}} = :inet.sockname(peer_listen)
      test_pid = self()

      spawn(fn ->
        case :gen_tcp.accept(peer_listen, 5_000) do
          {:ok, peer_sock} ->
            _ = :gen_tcp.controlling_process(peer_sock, test_pid)
            send(test_pid, {:peer_sock, peer_sock})

          {:error, reason} ->
            send(test_pid, {:peer_accept_error, reason})
        end
      end)

      on_exit(fn ->
        if is_port(peer_listen), do: :gen_tcp.close(peer_listen)
      end)

      conn = %Conn{tcp_allocate_conn(client_ip) | force_auth: true}

      challenge =
        Pipeline.process_message(%Conn{conn | message: encode_tcp_allocate(8_656_0610, username: username)})

      assert challenge.response.err_no == 401
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      key = :crypto.hash(:md5, "#{username}:#{realm}:#{password}")

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_tcp_allocate(8_656_0610, %{
                     username: username,
                     realm: realm,
                     nonce: nonce,
                     key: key
                   })
             }).response.class == :success

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_authed_request(:createperm, 8_656_0611, key, %{
                     xor_peer_address: {loopback, peer_port},
                     username: username,
                     realm: realm,
                     nonce: nonce
                   })
             }).response.class == :success

      connect_result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_authed_request(:connect, 8_656_0612, key, %{
                xor_peer_address: {loopback, peer_port},
                username: username,
                realm: realm,
                nonce: nonce
              })
        })

      assert connect_result.response.class == :success
      connection_id = Map.fetch!(connect_result.response.attrs, :connection_id)
      assert_receive {:peer_sock, peer_sock}, 5_000

      # RFC 6062: ConnectionBind is a new TCP connection (different client port).
      bind_conn = %Conn{conn | client_port: 9100}

      result =
        Pipeline.process_message(%Conn{
          bind_conn
          | message:
              encode_authed_request(:connection_bind, 8_656_0613, key, %{
                connection_id: connection_id,
                username: username,
                realm: realm,
                nonce: nonce
              })
        })

      assert result.response.class == :success
      assert {:ok, wire} = Conn.to_reply(result)
      bin = IO.iodata_to_binary(wire)
      assert {:ok, decoded} = Stun.decode(bin, key)
      assert decoded.class == :success
      assert decoded.method == :connection_bind
      assert decoded.integrity == true

      :gen_tcp.close(peer_sock)
    end

    test "passive peer connect registers inbound connection (ConnectionAttempt path)" do
      loopback = {127, 0, 0, 1}
      client_ip = {127, 0, 0, 121}
      test_pid = self()

      conn =
        %Conn{
          tcp_allocate_conn(client_ip)
          | client_socket:
              Xirsys.XTurn.ClientSocket.new(TCP, test_pid, client_ip, 9001)
        }

      alloc =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_tcp_allocate(8_656_0620)
        })

      assert alloc.response.class == :success
      {relay_ip, relay_port} = relay_addr(alloc)

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:createperm, 8_656_0621, %{
                     xor_peer_address: {loopback, 1}
                   })
             }).response.class == :success

      {:ok, peer_sock} = :gen_tcp.connect(relay_ip, relay_port, [:binary, active: false], 5_000)
      on_exit(fn -> if is_port(peer_sock), do: :gen_tcp.close(peer_sock) end)

      assert_receive {:turn_client, data}, 5_000
      assert {:ok, decoded} = Stun.decode(IO.iodata_to_binary(data))
      assert decoded.class == :indication
      assert decoded.method == :connection_attempt
      assert is_binary(decoded.attrs.connection_id)
      assert byte_size(decoded.attrs.connection_id) == 4
      assert Map.has_key?(decoded.attrs, :xor_peer_address)

      tuple5 = Xirsys.XTurn.Tuple5.to_map(Xirsys.XTurn.Tuple5.create(conn, :_))
      assert {:ok, [alloc_pid, _relay, _sock, _perms]} = Xirsys.XTurn.Allocate.Store.lookup(tuple5)

      assert wait_inbound_connection(alloc_pid)
    end

    test "second Connect to the same peer is 446" do
      loopback = {127, 0, 0, 1}
      client_ip = {127, 0, 0, 122}
      test_pid = self()

      {:ok, peer_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: loopback])
      {:ok, {_, peer_port}} = :inet.sockname(peer_listen)
      on_exit(fn -> if is_port(peer_listen), do: :gen_tcp.close(peer_listen) end)

      spawn(fn ->
        case :gen_tcp.accept(peer_listen, 5_000) do
          {:ok, peer_sock} ->
            _ = :gen_tcp.controlling_process(peer_sock, test_pid)
            send(test_pid, {:peer_sock, peer_sock})

          _ ->
            :ok
        end
      end)

      conn = tcp_allocate_conn(client_ip)

      assert Pipeline.process_message(%Conn{conn | message: encode_tcp_allocate(8_656_0630)}).response.class ==
               :success

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:createperm, 8_656_0631, %{
                     xor_peer_address: {loopback, peer_port}
                   })
             }).response.class == :success

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:connect, 8_656_0632, %{
                     xor_peer_address: {loopback, peer_port}
                   })
             }).response.class == :success

      assert_receive {:peer_sock, peer_sock}, 5_000

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:connect, 8_656_0633, %{
                xor_peer_address: {loopback, peer_port}
              })
        })

      assert result.response.err_no == 446
      :gen_tcp.close(peer_sock)
    end

    test "Connect to a closed peer port is 447" do
      loopback = {127, 0, 0, 1}
      client_ip = {127, 0, 0, 123}
      conn = tcp_allocate_conn(client_ip)

      assert Pipeline.process_message(%Conn{conn | message: encode_tcp_allocate(8_656_0640)}).response.class ==
               :success

      {:ok, peer_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: loopback])
      {:ok, {_, peer_port}} = :inet.sockname(peer_listen)
      :gen_tcp.close(peer_listen)

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:createperm, 8_656_0641, %{
                     xor_peer_address: {loopback, peer_port}
                   })
             }).response.class == :success

      result =
        Pipeline.process_message(%Conn{
          conn
          | message:
              encode_request(:connect, 8_656_0642, %{
                xor_peer_address: {loopback, peer_port}
              })
        })

      assert result.response.err_no == 447
    end

    test "Send indication on TCP relay control connection is dropped" do
      loopback = {127, 0, 0, 1}
      client_ip = {127, 0, 0, 124}
      conn = tcp_allocate_conn(client_ip)

      assert Pipeline.process_message(%Conn{conn | message: encode_tcp_allocate(8_656_0650)}).response.class ==
               :success

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   encode_request(:createperm, 8_656_0651, %{
                     xor_peer_address: {loopback, 9_999}
                   })
             }).response.class == :success

      assert Pipeline.process_message(%Conn{
               conn
               | message:
                   Stun.encode(%Stun{
                     class: :indication,
                     method: :send,
                     transactionid: 8_656_0652,
                     fingerprint: false,
                     attrs: %{
                       xor_peer_address: {loopback, 9_999},
                       data: "nope"
                     }
                   })
             }) == false
    end
  end

  defp authed_allocate(client_ip, username, password, tid) do
    conn = %Conn{allocate_conn(client_ip) | force_auth: true}
    challenge = Pipeline.process_message(%Conn{conn | message: encode_allocate(tid, username: username)})
    assert challenge.response.err_no == 401
    nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
    realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
    key = :crypto.hash(:md5, "#{username}:#{realm}:#{password}")

    authed =
      Stun.encode(%Stun{
        class: :request,
        method: :allocate,
        transactionid: tid,
        fingerprint: false,
        integrity: true,
        key: key,
        attrs: %{
          requested_transport: @udp,
          username: username,
          realm: realm,
          nonce: nonce
        }
      })

    Pipeline.process_message(%Conn{conn | message: authed})
  end

  defp allocate_conn(client_ip) do
    %Conn{
      @conn
      | client_ip: client_ip,
        client_socket: fake_client_socket(UDP)
    }
  end

  defp tcp_allocate_conn(client_ip) do
    %Conn{
      @conn
      | client_ip: client_ip,
        client_socket: fake_client_socket(TCP)
    }
  end

  defp encode_allocate(tid, extra \\ []) do
    {additional, extra} = Keyword.pop(extra, :additional)

    attrs =
      %{requested_transport: @udp}
      |> Map.merge(Enum.into(extra, %{}))

    bin =
      Stun.encode(%Stun{
        class: :request,
        method: :allocate,
        transactionid: tid,
        fingerprint: false,
        attrs: attrs
      })

    append_tlv(bin, @additional_type, additional)
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

  defp encode_tcp_allocate(tid, extra \\ [])

  defp encode_tcp_allocate(tid, extra) when is_list(extra) do
    encode_tcp_allocate(tid, Enum.into(extra, %{}))
  end

  defp encode_tcp_allocate(tid, attrs) when is_map(attrs) do
    {key, attrs} = Map.pop(attrs, :key)

    Stun.encode(%Stun{
      class: :request,
      method: :allocate,
      transactionid: tid,
      fingerprint: false,
      integrity: key != nil,
      key: key,
      attrs: Map.put(attrs, :requested_transport, <<6, 0, 0, 0>>)
    })
  end

  defp encode_authed_request(method, tid, key, attrs) do
    Stun.encode(%Stun{
      class: :request,
      method: method,
      transactionid: tid,
      fingerprint: false,
      integrity: true,
      key: key,
      attrs: attrs
    })
  end

  defp append_tlv(bin, _type, nil), do: bin

  defp append_tlv(bin, type, value) when is_binary(value) do
    <<msg_type::16, len::16, rest::binary>> = bin
    pad = rem(4 - rem(byte_size(value), 4), 4)
    tlv = <<type::16, byte_size(value)::16, value::binary, 0::size(pad * 8)>>
    <<msg_type::16, len + byte_size(tlv)::16, rest::binary, tlv::binary>>
  end

  defp relay_addr(conn) do
    case conn.response.attrs.xor_relayed_address do
      [{ip, port} | _] -> {ip, port}
      {ip, port} -> {ip, port}
    end
  end

  defp restore_env(app, key, value) do
    case value do
      nil -> Application.delete_env(app, key)
      value -> Application.put_env(app, key, value)
    end
  end

  defp fake_client_socket(transport) do
    Xirsys.XTurn.ClientSocket.new(transport, :fake, {127, 0, 0, 1}, 9999)
  end

  defp wait_inbound_connection(alloc_pid, attempts \\ 50) do
    inbound? =
      :sys.get_state(alloc_pid).connections
      |> Enum.any?(fn {_id, entry} -> entry.direction == :inbound and entry.status == :pending end)

    case {inbound?, attempts} do
      {true, _} -> true
      {false, 0} -> false
      {false, n} ->
        Process.sleep(10)
        wait_inbound_connection(alloc_pid, n - 1)
    end
  end
end
