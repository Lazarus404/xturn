defmodule Xirsys.XTurn.Auth.NonceStoreTest do
  use ExUnit.Case, async: false

  alias Xirsys.XTurn.Auth.NonceStore

  setup do
    old_max_age = Application.get_env(:xturn, :nonce_max_age_ms)

    on_exit(fn ->
      Application.put_env(:xturn, :nonce_max_age_ms, old_max_age)
    end)

    :ok
  end

  test "issue and validate roundtrip" do
    client_key = unique_client_key()
    nonce = NonceStore.issue(client_key)
    assert is_binary(nonce)
    assert NonceStore.validate(client_key, nonce) == :ok
  end

  test "missing nonce is rejected" do
    client_key = unique_client_key()
    NonceStore.issue(client_key)
    assert NonceStore.validate(client_key, nil) == :missing
    assert NonceStore.validate(client_key, "unknown") == :mismatch
  end

  test "unknown client is missing" do
    assert NonceStore.validate(unique_client_key(), "abc") == :missing
  end

  test "stale nonce after max age" do
    Application.put_env(:xturn, :nonce_max_age_ms, 1)
    client_key = unique_client_key()
    nonce = NonceStore.issue(client_key)
    Process.sleep(5)
    assert NonceStore.validate(client_key, nonce) == :stale
  end

  test "re-issue replaces the stored nonce" do
    client_key = unique_client_key()
    first = NonceStore.issue(client_key)
    second = NonceStore.issue(client_key)
    assert first != second
    assert NonceStore.validate(client_key, first) == :mismatch
    assert NonceStore.validate(client_key, second) == :ok
  end

  test "validate_for_ip accepts a nonce issued to the same IP on another port" do
    ip = {127, 0, 0, 9}
    nonce = NonceStore.issue({ip, 3478})
    assert NonceStore.validate_for_ip(ip, nonce) == :ok
    assert NonceStore.validate({ip, 9999}, nonce) == :missing
    assert NonceStore.validate_for_ip({10, 0, 0, 1}, nonce) == :missing
  end

  defp unique_client_key do
    {{127, 0, 0, 1}, System.unique_integer([:positive])}
  end
end
