defmodule XTurn.TestSupport.IgnoringActive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :active

  @impl true
  def hooks, do: [:egress, :ingress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, _opts), do: :ignore

  @impl true
  def handle_frame(payload, _frame, _state), do: {:ok, payload}
end
