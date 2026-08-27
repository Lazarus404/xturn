defmodule XTurn.TestSupport.DropperActive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :active

  @impl true
  def hooks, do: [:egress, :ingress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, _opts), do: {:ok, nil}

  @impl true
  def handle_frame(_payload, _frame, _state), do: :drop
end
