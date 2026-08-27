defmodule Xirsys.XTurn.Auth.AccessTokenTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.Auth.AccessToken

  @key :crypto.hash(:sha256, "test-aead-key-material")
  @server "turn.example.com"

  test "mint/verify round-trips mac_key" do
    mac_key = :crypto.strong_rand_bytes(20)
    token = AccessToken.mint(mac_key, 60, @key, @server)
    assert {:ok, ^mac_key} = AccessToken.verify(token, @key, @server)
  end

  test "verify accepts RFC7635 plaintext with server name AAD" do
    mac_key = :crypto.strong_rand_bytes(20)
    sec = System.system_time(:second)
    ts = <<sec::48, 0::16>>
    plaintext = <<20::16, mac_key::binary, ts::binary, 300::32>>
    nonce = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, @key, nonce, plaintext, @server, true)

    token = <<byte_size(nonce)::16, nonce::binary, ciphertext::binary, tag::binary>>
    assert {:ok, ^mac_key} = AccessToken.verify(token, @key, @server)
  end

  test "verify rejects wrong server name AAD" do
    mac_key = :crypto.strong_rand_bytes(20)
    sec = System.system_time(:second)
    ts = <<sec::48, 0::16>>
    plaintext = <<20::16, mac_key::binary, ts::binary, 300::32>>
    nonce = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, @key, nonce, plaintext, @server, true)

    token = <<byte_size(nonce)::16, nonce::binary, ciphertext::binary, tag::binary>>
    assert {:error, :invalid} = AccessToken.verify(token, @key, "other.example.com")
  end

  test "verify rejects expired token" do
    mac_key = :crypto.strong_rand_bytes(20)
    past = System.system_time(:second) - 10
    token = AccessToken.mint(mac_key, 0, @key, @server, past)
    assert {:error, :invalid} = AccessToken.verify(token, @key, @server)
  end
end
