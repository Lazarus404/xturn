defmodule Xirsys.XTurn.Accumulators.StunTurnTest do
  use ExUnit.Case, async: true

  alias Xirsys.XTurn.Accumulators.StunTurn

  test "parses a complete STUN message in one push" do
    body = <<>>
    frame = stun_frame(byte_size(body), body)
    acc = StunTurn.init([]) |> StunTurn.push(frame, %{})

    assert {:ok, ^frame, %{}, acc} = StunTurn.pop(acc)
    assert {:more, _} = StunTurn.pop(acc)
  end

  test "parses split STUN bytes" do
    body = <<"hello">>
    frame = stun_frame(byte_size(body), body)

    acc =
      frame
      |> split_push(3)
      |> elem(0)

    assert {:ok, ^frame, %{}, _} = StunTurn.pop(acc)
  end

  test "parses channel data with 4-byte-aligned payload without extra padding" do
    payload = <<"abcd">>
    frame = channel_frame(payload)
    assert byte_size(frame) == 8

    acc = StunTurn.init([]) |> StunTurn.push(frame, %{})
    assert {:ok, ^frame, %{}, _} = StunTurn.pop(acc)
  end

  test "datagram framing parses unpadded channel data with a non-aligned length" do
    payload = <<"abcde">>
    frame = channel_frame(payload)
    assert byte_size(frame) == 9, "unpadded frame is header + payload only"

    acc = StunTurn.init(framing: :datagram) |> StunTurn.push(frame, %{})

    assert {:ok, ^frame, %{}, _} = StunTurn.pop(acc),
           "an unpadded, non-4-aligned ChannelData frame must be relayed, not dropped"
  end

  test "datagram framing still accepts optional padding, and excludes it from the message" do
    payload = <<"abcde">>
    frame = channel_frame(payload)
    padded = pad_frame(frame)
    assert byte_size(padded) == 12

    acc = StunTurn.init(framing: :datagram) |> StunTurn.push(padded, %{})

    assert {:ok, ^frame, %{}, _} = StunTurn.pop(acc),
           "padding must never be relayed as part of the payload"
  end

  test "stream framing consumes padding without emitting it, and stays in sync" do
    first = channel_frame(<<"abcde">>)
    second = channel_frame(<<"wxyz">>)

    acc =
      StunTurn.init(framing: :stream)
      |> StunTurn.push(pad_frame(first) <> pad_frame(second), %{})

    assert {:ok, ^first, %{}, acc} = StunTurn.pop(acc),
           "padding must be stripped from the emitted message"

    assert {:ok, ^second, %{}, acc} = StunTurn.pop(acc),
           "the following frame must still parse, proving the padding was consumed"

    assert {:more, _} = StunTurn.pop(acc)
  end

  test "stream framing waits for mandatory padding rather than desyncing" do
    frame = channel_frame(<<"abcde">>)

    acc = StunTurn.init(framing: :stream) |> StunTurn.push(frame, %{})

    assert {:more, _} = StunTurn.pop(acc),
           "over TCP the padding is mandatory, so an unpadded frame is incomplete"
  end

  test "parses split channel data bytes" do
    frame = channel_frame(<<"abcde">>)

    acc =
      pad_frame(frame)
      |> split_push(5)
      |> elem(0)

    assert {:ok, ^frame, %{}, _} = StunTurn.pop(acc)
  end

  test "surfaces buffer overflow" do
    acc = StunTurn.init(max_size: 8) |> StunTurn.push(<<0::size(96), 0::size(96)>>, %{})

    assert {:error, :buffer_overflow, acc} = StunTurn.pop(acc)
    assert {:more, _} = StunTurn.pop(acc)
  end

  defp stun_frame(body_len, body) do
    <<0::2, 0::14, body_len::16, 0::32, 0::96, body::binary>>
  end

  defp channel_frame(payload) do
    <<1::2, 0::14, byte_size(payload)::16, payload::binary>>
  end

  defp pad_frame(frame) do
    padded_size = Bitwise.band(byte_size(frame) + 3, -4)
    frame <> :binary.copy(<<0>>, padded_size - byte_size(frame))
  end

  defp split_push(binary, size) do
    Enum.reduce(chunk_binary(binary, size), {StunTurn.init([]), %{}}, fn chunk, {acc, _} ->
      {StunTurn.push(acc, chunk, %{}), %{}}
    end)
  end

  defp chunk_binary(<<>>, _size), do: []

  defp chunk_binary(binary, size) do
    if byte_size(binary) <= size do
      [binary]
    else
      <<head::binary-size(^size), rest::binary>> = binary
      [head | chunk_binary(rest, size)]
    end
  end
end
