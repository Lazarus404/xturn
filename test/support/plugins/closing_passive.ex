defmodule XTurn.TestSupport.ClosingPassive do
  @behaviour Xirsys.XTurn.Plugin

  @impl true
  def mode, do: :passive

  @impl true
  def hooks, do: [:egress]

  @impl true
  def attach?(_allocation, _opts), do: true

  @impl true
  def init(_allocation, opts), do: {:ok, Keyword.get(opts, :notify, self())}

  @impl true
  def handle_frame(_payload, _frame, notify), do: {:ok, notify}

  @impl true
  def handle_close(reason, notify) do
    send(notify, {:closed, reason})
    :ok
  end
end
