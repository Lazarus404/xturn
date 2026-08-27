defmodule XTurn.TestSupport.BlockingPassive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :passive

  @impl true
  def hooks, do: [:egress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, _opts), do: {:ok, nil}

  @impl true
  def handle_frame(_payload, _frame, state) do
    receive do
      :release -> {:ok, state}
    end
  end

  @impl true
  def handle_close(_reason, _state), do: :ok
end
