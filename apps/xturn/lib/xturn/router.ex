defmodule Xirsys.Router.Server do
  use Maru.Router

  alias Xirsys.Turn.Allocate.Client, as: AllocateClient

  namespace :allocation do
    desc "returns the current number of allocations on the server"
    get do
      {:ok, workers} = AllocateClient.count
      json(conn, %{ status: :ok, count: workers })
    end
  end
end