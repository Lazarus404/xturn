defmodule XTurn.TestSupport.DecliningActive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :active

  @impl true
  def hooks, do: [:egress, :ingress]

  @impl true
  def attach?(_allocation, _opts), do: false

  @impl true
  def init(_allocation, _opts), do: {:ok, nil}

  @impl true
  def handle_frame(payload, _frame, _state), do: {:ok, payload}
end
