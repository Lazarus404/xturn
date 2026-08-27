defmodule Xirsys.XTurn.RFC8489Test do
  @moduledoc """
  RFC 8489 STUN usage holes that RFC 8656 5 requires (see RFC-8489 / RFC-8656).
  Codec coverage lives in xmedialib/test/rfc8489_test.exs. xsockets has no
  STUN semantics.

  Skipped here (same as the checklists): SASLprep.
  """
  use ExUnit.Case, async: false
  import Bitwise

  alias XMediaLib.Stun
  alias Xirsys.XTurn.{Conn, Pipeline}
  alias Xirsys.XTurn.Auth.Client, as: Auth

  @conn %Conn{
    client_ip: {127, 0, 0, 80},
    client_port: 9001,
    server_ip: {127, 0, 0, 1},
    server_port: 3478
  }

  @realm "xirsys.com"
  @udp <<17, 0, 0, 0>>
  @sha256_type 0x001C
  @cookie "obMatJos2"

  @md5 0x0001
  @sha256_alg 0x0002
  @password_algorithms <<@md5::16, 0::16, @sha256_alg::16, 0::16>>
  @password_algorithm_sha256 <<@sha256_alg::16, 0::16>>

  describe "nonce cookie (RFC 8489 9.2 / RFC 8656 5)" do
    test "401 NONCE is obMatJos2 + 4-char feature flags + at least 8 more characters" do
      conn = challenge_conn({127, 0, 0, 81}, 8_489_0101)
      nonce = Map.fetch!(conn.decoded_message.attrs, :nonce)
      assert_nonce_cookie(nonce)
    end

    test "438 Stale Nonce also carries the nonce cookie" do
      client_ip = {127, 0, 0, 82}
      username = "rfc8489_stale"
      password = "rfc8489_stale_pass"
      Auth.add_user(username, password, "/", "server")

      old_max = Application.get_env(:xturn, :nonce_max_age_ms)
      Application.put_env(:xturn, :nonce_max_age_ms, 1)
      on_exit(fn -> Application.put_env(:xturn, :nonce_max_age_ms, old_max) end)

      challenge = challenge_conn(client_ip, 8_489_0102, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      key = :crypto.hash(:md5, "#{username}:#{@realm}:#{password}")

      authed =
        encode_allocate(8_489_0102,
          username: username,
          realm: realm,
          nonce: nonce,
          integrity: true,
          key: key
        )

      Process.sleep(5)

      stale =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert stale.response.err_no == 438
      assert_nonce_cookie(Map.fetch!(stale.decoded_message.attrs, :nonce))
    end
  end

  describe "PASSWORD-ALGORITHMS on TURN 401/438 (RFC 8489 9.2.4 / RFC 8656 5)" do
    test "401 lists PASSWORD-ALGORITHMS and sets cookie bit 0" do
      conn = challenge_conn({127, 0, 0, 83}, 8_489_0201)
      attrs = conn.decoded_message.attrs
      palgs = Map.get(attrs, :password_algorithms)
      assert is_binary(palgs)
      assert :binary.match(palgs, <<@sha256_alg::16>>) != :nomatch
      {flags, _rest} = assert_nonce_cookie(attrs.nonce)
      <<bit0::1, bit1::1, _::22>> = flags
      assert bit0 == 1
      assert bit1 == 1
    end

    test "401 has REALM and NONCE and omits USERNAME, USERHASH, and integrity" do
      conn = challenge_conn({127, 0, 0, 84}, 8_489_0202)
      attrs = conn.decoded_message.attrs
      assert attrs.realm == @realm
      assert is_binary(attrs.nonce)
      refute Map.has_key?(attrs, :username)
      refute Map.has_key?(attrs, :userhash)
      refute Map.has_key?(attrs, :message_integrity)
      refute Map.has_key?(attrs, :message_integrity_sha256)
    end

    test "authenticated request that does not echo PASSWORD-ALGORITHMS is 400" do
      client_ip = {127, 0, 0, 85}
      username = "rfc8489_echo"
      password = "rfc8489_echo_pass"
      Auth.add_user(username, password, "/", "server")

      challenge = challenge_conn(client_ip, 8_489_0203, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      palgs = Map.get(challenge.decoded_message.attrs, :password_algorithms)
      assert is_binary(palgs)
      key = :crypto.hash(:md5, "#{username}:#{@realm}:#{password}")

      mismatched = <<@md5::16, 0::16>>
      refute mismatched == palgs

      authed =
        encode_allocate(8_489_0203,
          username: username,
          realm: realm,
          nonce: nonce,
          password_algorithms: mismatched,
          integrity: true,
          key: key
        )

      conn =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert conn.response.err_no == 400
    end
  end

  describe "MESSAGE-INTEGRITY-SHA256 on Allocate (RFC 8489 9.2.4 / RFC 8656 5)" do
    test "Allocate with SHA-256 password key and HMAC succeeds; reply uses SHA-256" do
      client_ip = {127, 0, 0, 86}
      username = "rfc8489_sha256"
      password = "rfc8489_sha256_pass"
      Auth.add_user(username, password, "/", "server")

      challenge = challenge_conn(client_ip, 8_489_0301, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      palgs = Map.get(challenge.decoded_message.attrs, :password_algorithms)
      assert is_binary(palgs)
      key = :crypto.hash(:sha256, "#{username}:#{@realm}:#{password}")

      authed =
        encode_allocate(8_489_0301,
          username: username,
          realm: realm,
          nonce: nonce,
          password_algorithms: palgs,
          password_algorithm: @password_algorithm_sha256,
          integrity: :sha256,
          key: key
        )

      allocated =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert allocated.response.class == :success
      {:ok, reply} = Conn.to_reply(allocated)
      assert tlv_present?(reply, @sha256_type)
      assert {:ok, decoded} = Stun.decode(reply, key)
      assert decoded.integrity == :sha256
    end

    test "SHA-256 HMAC mismatch with complete credentials is 401" do
      client_ip = {127, 0, 0, 87}
      username = "rfc8489_sha256_bad"
      password = "rfc8489_sha256_bad_pass"
      Auth.add_user(username, password, "/", "server")

      challenge = challenge_conn(client_ip, 8_489_0302, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      palgs = Map.get(challenge.decoded_message.attrs, :password_algorithms, @password_algorithms)
      wrong_key = :crypto.hash(:sha256, "#{username}:#{@realm}:wrong")

      authed =
        encode_allocate(8_489_0302,
          username: username,
          realm: realm,
          nonce: nonce,
          password_algorithms: palgs,
          password_algorithm: @password_algorithm_sha256,
          integrity: :sha256,
          key: wrong_key
        )

      conn =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert conn.response.err_no == 401
      assert Map.get(conn.decoded_message.attrs, :realm) == @realm
    end
  end

  describe "USERHASH lookup (RFC 8489 14.4 / 9.2)" do
    test "Allocate with USERHASH (no USERNAME) and SHA1 integrity succeeds" do
      client_ip = {127, 0, 0, 88}
      username = "rfc8489_userhash"
      password = "rfc8489_userhash_pass"
      Auth.add_user(username, password, "/", "server")
      hash = :crypto.hash(:sha256, "#{username}:#{@realm}")

      challenge = challenge_conn(client_ip, 8_489_0401, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      key = :crypto.hash(:md5, "#{username}:#{@realm}:#{password}")

      authed =
        encode_allocate(8_489_0401,
          userhash: hash,
          realm: realm,
          nonce: nonce,
          integrity: true,
          key: key
        )

      allocated =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert allocated.response.class == :success
    end

    test "Allocate with USERHASH and SHA-256 integrity succeeds" do
      client_ip = {127, 0, 0, 89}
      username = "rfc8489_userhash_sha256"
      password = "rfc8489_userhash_sha256_pass"
      Auth.add_user(username, password, "/", "server")
      hash = :crypto.hash(:sha256, "#{username}:#{@realm}")

      challenge = challenge_conn(client_ip, 8_489_0402, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      palgs = Map.get(challenge.decoded_message.attrs, :password_algorithms)
      key = :crypto.hash(:sha256, "#{username}:#{@realm}:#{password}")

      authed =
        encode_allocate(8_489_0402,
          userhash: hash,
          realm: realm,
          nonce: nonce,
          password_algorithms: palgs,
          password_algorithm: @password_algorithm_sha256,
          integrity: :sha256,
          key: key
        )

      allocated =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert allocated.response.class == :success
    end

    test "unknown USERHASH is 401" do
      client_ip = {127, 0, 0, 90}
      unknown_hash = :crypto.hash(:sha256, "nobody:#{@realm}")

      challenge = challenge_conn(client_ip, 8_489_0403)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      key = :crypto.hash(:md5, "nobody:#{@realm}:wrong")

      authed =
        encode_allocate(8_489_0403,
          userhash: unknown_hash,
          realm: realm,
          nonce: nonce,
          integrity: true,
          key: key
        )

      conn =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert conn.response.err_no == 401
    end
  end

  describe "300 Try Alternate (RFC 8489 10 / RFC 8656 7.2)" do
    @alternate {{203, 0, 113, 10}, 3478}

    test "try_alternate drain flag returns 300 with ALTERNATE-SERVER" do
      client_ip = {127, 0, 0, 91}
      username = "rfc8489_try_alt"
      password = "rfc8489_try_alt_pass"
      Auth.add_user(username, password, "/", "server")

      old_server = Application.get_env(:xturn, :alternate_server)
      old_drain = Application.get_env(:xturn, :try_alternate)
      Application.put_env(:xturn, :alternate_server, @alternate)
      Application.put_env(:xturn, :try_alternate, true)

      on_exit(fn ->
        restore_env(:xturn, :alternate_server, old_server)
        restore_env(:xturn, :try_alternate, old_drain)
      end)

      challenge = challenge_conn(client_ip, 8_489_0501, username)
      nonce = Map.fetch!(challenge.decoded_message.attrs, :nonce)
      realm = Map.fetch!(challenge.decoded_message.attrs, :realm)
      key = :crypto.hash(:md5, "#{username}:#{@realm}:#{password}")

      authed =
        encode_allocate(8_489_0501,
          username: username,
          realm: realm,
          nonce: nonce,
          integrity: true,
          key: key
        )

      conn =
        Pipeline.process_message(%Conn{
          allocate_conn(client_ip)
          | message: authed,
            force_auth: true
        })

      assert conn.response.err_no == 300
      {:ok, reply} = Conn.to_reply(conn)
      assert tlv_present?(reply, 0x000E)
      refute tlv_present?(reply, 0x0008)
      refute tlv_present?(reply, 0x001C)
      assert {:ok, decoded} = Stun.decode(reply)
      assert decoded.attrs.alternate_server == @alternate
      refute Map.has_key?(decoded.attrs, :username)
      refute Map.has_key?(decoded.attrs, :message_integrity)
    end

    test "invalid RESERVATION-TOKEN stays 508 even with alternate_server configured" do
      client_ip = {127, 0, 0, 92}
      old_server = Application.get_env(:xturn, :alternate_server)
      Application.put_env(:xturn, :alternate_server, @alternate)
      on_exit(fn -> restore_env(:xturn, :alternate_server, old_server) end)

      conn = allocate_conn(client_ip)

      result =
        Pipeline.process_message(%Conn{
          conn
          | message: encode_allocate(8_489_0502, reservation_token: <<9, 9, 9, 9, 9, 9, 9, 9>>)
        })

      assert result.response.err_no == 508
    end
  end

  defp restore_env(app, key, value) do
    case value do
      nil -> Application.delete_env(app, key)
      value -> Application.put_env(app, key, value)
    end
  end

  defp challenge_conn(client_ip, tid, username \\ "rfc8489_anon") do
    conn =
      Pipeline.process_message(%Conn{
        allocate_conn(client_ip)
        | message: encode_allocate(tid, username: username),
          force_auth: true
      })

    assert conn.response.err_no == 401
    conn
  end

  defp allocate_conn(client_ip) do
    %Conn{
      @conn
      | client_ip: client_ip,
        client_socket: fake_client_socket()
    }
  end

  defp encode_allocate(tid, opts) do
    {integrity, opts} = Keyword.pop(opts, :integrity, false)
    {key, opts} = Keyword.pop(opts, :key, nil)
    {palgs, opts} = Keyword.pop(opts, :password_algorithms)
    {palg, opts} = Keyword.pop(opts, :password_algorithm)

    sha256? = integrity == :sha256

    bin =
      Stun.encode(%Stun{
        class: :request,
        method: :allocate,
        transactionid: tid,
        fingerprint: false,
        integrity: if(sha256?, do: false, else: integrity),
        key: if(sha256?, do: nil, else: key),
        attrs: Map.put(Map.new(opts), :requested_transport, @udp)
      })

    bin
    |> append_tlv(0x8002, palgs)
    |> append_tlv(0x001D, palg)
    |> then(fn msg -> if sha256?, do: with_sha256_integrity(msg, key), else: msg end)
  end

  defp append_tlv(bin, _type, nil), do: bin

  defp append_tlv(bin, type, value) when is_binary(value) do
    <<msg_type::16, len::16, rest::binary>> = bin
    pad = rem(4 - rem(byte_size(value), 4), 4)
    tlv = <<type::16, byte_size(value)::16, value::binary, 0::size(pad * 8)>>
    <<msg_type::16, len + byte_size(tlv)::16, rest::binary, tlv::binary>>
  end

  defp with_sha256_integrity(bin, key) do
    <<type::16, _len::16, rest::binary>> = bin
    new_len = byte_size(bin) - 20 + 36
    msg = <<type::16, new_len::16, rest::binary>>
    hmac = :crypto.mac(:hmac, :sha256, key, msg)
    msg <> <<@sha256_type::16, 32::16, hmac::binary>>
  end

  defp assert_nonce_cookie(nonce) when is_binary(nonce) do
    assert String.starts_with?(nonce, @cookie)
    <<_::binary-size(9), flags_b64::binary-size(4), rest::binary>> = nonce
    assert byte_size(rest) >= 8
    assert {:ok, flags} = Base.decode64(flags_b64)
    assert byte_size(flags) == 3
    {flags, rest}
  end

  defp tlv_present?(stun_binary, attr_type) do
    <<_type::16, len::16, _cookie::32, _tid::96, attrs::binary>> = stun_binary
    scan_type(attrs, len, attr_type)
  end

  defp scan_type(_bin, remaining, _attr_type) when remaining <= 0, do: false

  defp scan_type(<<type::16, item_len::16, rest::binary>>, remaining, attr_type) do
    pad =
      case rem(item_len, 4) do
        0 -> 0
        r -> 4 - r
      end

    <<_value::binary-size(item_len), _pad::binary-size(pad), tail::binary>> = rest
    type == attr_type or scan_type(tail, remaining - 4 - item_len - pad, attr_type)
  end

  defp fake_client_socket do
    Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, :fake, {127, 0, 0, 1}, 9999)
  end
end
