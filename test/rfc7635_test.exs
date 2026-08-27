defmodule Xirsys.XTurn.RFC7635Test do
  use ExUnit.Case, async: false

  alias XMediaLib.Stun
  alias Xirsys.XTurn.Auth.AccessToken
  alias Xirsys.XTurn.{Conn, Pipeline}

  defp conn(client_ip) do
    %Conn{
      client_ip: client_ip,
      client_port: 9001,
      server_ip: {127, 0, 0, 1},
      server_port: 3478,
      client_socket:
        Xirsys.XTurn.ClientSocket.new(XSockets.Transport.UDP, :fake, client_ip, 9001)
    }
  end

  @aead_key :crypto.hash(:sha256, "rfc7635-test-aead-key")
  @as_uri "https://as.example.com/turn"

  setup do
    saved = Application.get_env(:xturn, :third_party_auth)
    auth_saved = Application.get_env(:xturn, :authentication)

    on_exit(fn ->
      Application.put_env(:xturn, :third_party_auth, saved)
      Application.put_env(:xturn, :authentication, auth_saved)
    end)

    Application.put_env(:xturn, :authentication, %{required: true})

    Application.put_env(:xturn, :third_party_auth,
      enabled: true,
      as_uri: @as_uri,
      aead_key: @aead_key,
      server_name: "turn.example.com"
    )

    :ok
  end

  test "401 includes THIRD-PARTY-AUTHORIZATION when enabled" do
    conn = %Conn{conn({127, 0, 0, 130}) | force_auth: true}

    result =
      Pipeline.process_message(%Conn{
        conn
        | message: encode_allocate(7_635_0101)
      })

    assert result.response.err_no == 401
    assert result.decoded_message.attrs.third_party_authorization == @as_uri
    assert Map.has_key?(result.decoded_message.attrs, :nonce)
    assert Map.has_key?(result.decoded_message.attrs, :realm)
  end

  test "valid ACCESS-TOKEN allocates without long-term credentials" do
    mac_key = :crypto.strong_rand_bytes(20)
    token = AccessToken.mint(mac_key, 300, @aead_key)
    conn = %Conn{conn({127, 0, 0, 131}) | force_auth: true}

    result =
      Pipeline.process_message(%Conn{
        conn
        | message: encode_allocate(7_635_0102, access_token: token, key: mac_key)
      })

    assert result.response.class == :success
  end

  test "garbage ACCESS-TOKEN is 401" do
    conn = %Conn{conn({127, 0, 0, 132}) | force_auth: true}

    result =
      Pipeline.process_message(%Conn{
        conn
        | message:
            encode_allocate(7_635_0103,
              access_token: "not-a-valid-token",
              key: :crypto.strong_rand_bytes(20)
            )
      })

    assert result.response.err_no == 401
  end

  test "when disabled, ACCESS-TOKEN is unknown required (420)" do
    Application.put_env(:xturn, :third_party_auth, enabled: false)
    conn = %Conn{conn({127, 0, 0, 133}) | force_auth: true}

    result =
      Pipeline.process_message(%Conn{
        conn
        | message: encode_allocate(7_635_0104, access_token: "opaque")
      })

    assert result.response.err_no == 420
    refute Map.has_key?(result.response.attrs || %{}, :third_party_authorization)
  end

  defp encode_allocate(tid, extra \\ []) do
    {key, extra} = Keyword.pop(extra, :key)

    attrs =
      extra
      |> Enum.into(%{})
      |> Map.put(:requested_transport, <<17, 0, 0, 0>>)

    Stun.encode(%Stun{
      class: :request,
      method: :allocate,
      transactionid: tid,
      fingerprint: false,
      integrity: is_binary(key),
      key: key,
      attrs: attrs
    })
  end
end
