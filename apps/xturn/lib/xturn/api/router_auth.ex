defmodule Xirsys.API.Router.Auth do
  use Maru.Router

  alias Xirsys.Turn.Auth.Client, as: AuthClient

  namespace :auth do
    desc("Adds a user to the user list")

    params do
      optional(:username, type: String)
      optional(:password, type: String)
      # This is used for analytics purposes. Maybe a room name or project name
      optional(:namespace, type: String)
      # id of the account creating the user. Useful for analytics and billing
      optional(:peer_id, type: String)
    end

    post do
      if not params[:username] or not params[:password] do
        {:ok, u, p} =
          AuthClient.create_user(
            params[:namespace] || "",
            params[:peer_id] || ""
          )

        json(conn, %{status: :ok, username: u, password: p})
      else
        {:ok, u, p} =
          AuthClient.add_user(
            params[:username],
            params[:password],
            params[:namespace] || "",
            params[:peer_id] || ""
          )

        json(conn, %{status: :ok, username: u, password: p})
      end
    end
  end
end
