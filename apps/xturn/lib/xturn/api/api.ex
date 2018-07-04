defmodule Xirsys.API do
  use Maru.Router

  before do
    plug Plug.Parsers,
      pass: ["*/*"],
      json_decoder: Poison,
      parsers: [:urlencoded, :json, :multipart]
  end

  mount Xirsys.API.Router.Auth
  mount Xirsys.API.Router.Allocation

  rescue_from :all do
    conn
    |> put_status(500)
    |> text("Server Error")
  end
end