defmodule Xirsys.API do
  use Maru.Router

  mount Xirsys.Router.Auth

  before do
    plug Plug.Parsers,
      pass: ["*/*"],
      json_decoder: Poison,
      parsers: [:urlencoded, :json, :multipart]
  end

  rescue_from :all do
    conn
    |> put_status(500)
    |> text("Server Error")
  end
end