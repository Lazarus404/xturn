defmodule XTurn.TestSupport.SlowActive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :active

  @impl true
  def hooks, do: [:egress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, opts), do: {:ok, Keyword.get(opts, :sleep_ms, 10)}

  @impl true
  def handle_frame(payload, _frame, sleep_ms) do
    Process.sleep(sleep_ms)
    {:ok, payload}
  end
end
