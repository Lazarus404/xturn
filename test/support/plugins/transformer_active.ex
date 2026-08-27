defmodule XTurn.TestSupport.TransformerActive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :active

  @impl true
  def hooks, do: [:egress, :ingress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, opts), do: {:ok, Keyword.get(opts, :suffix, "x")}

  @impl true
  def handle_frame(payload, _frame, suffix), do: {:ok, payload <> suffix}
end
