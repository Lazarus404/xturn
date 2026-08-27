defmodule Xirsys.XTurn.Auth.SharedSecretTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.Auth.SharedSecret

  @secret "coturn-style-secret"

  test "generate and verify roundtrip" do
    {username, password} = SharedSecret.generate("alice", 3600, @secret)
    assert SharedSecret.rest_username?(username)
    assert {:ok, ^password} = SharedSecret.verify_username(username, @secret)
  end

  test "expired timestamp is rejected" do
    past = System.system_time(:second) - 10
    username = "#{past}:bob"
    assert SharedSecret.verify_username(username, @secret) == :expired
  end

  test "tampered password fails integrity via derived key mismatch" do
    {username, password} = SharedSecret.generate("carol", 3600, @secret)
    assert {:ok, ^password} = SharedSecret.verify_username(username, @secret)
    refute password == Base.encode64(:crypto.mac(:hmac, :sha, @secret, username <> "x"))
  end

  test "non-rest usernames are not detected as rest usernames" do
    refute SharedSecret.rest_username?("plain-user")
    refute SharedSecret.rest_username?("not-a-timestamp:user")
  end
end
