defmodule XTurn.TestSupport.CrashingPassive do
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
  def handle_frame(_payload, _frame, _state), do: raise "passive crash"
end
