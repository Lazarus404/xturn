ExUnit.start()

for path <- Path.wildcard("_build/test/lib/*/ebin") do
  Code.append_path(path)
end

Application.ensure_all_started(:telemetry)

Xirsys.XTurn.Allocate.Store.init()
Xirsys.XTurn.Channels.Store.init()
Xirsys.XTurn.Permissions.Store.init()
Xirsys.XTurn.Auth.Table.init()
Xirsys.XTurn.Allocate.Bytes.init()
Xirsys.XTurn.Plugin.Table.init()
Xirsys.XTurn.ReservationStore.init()
:ok = Xirsys.XTurn.ListenRegistry.ensure!()

for start <- [
      {Xirsys.XTurn.PacketLog.Writer, :start_link, []},
      {Xirsys.XTurn.ClientWorker.Pool, :start_link, []},
      {Xirsys.XTurn.RelayIngress, :start_link, []},
      {Xirsys.XTurn.Plugin.Supervisor, :start_link, []},
      {Xirsys.XTurn.Allocate.Supervisor, :start_link, [Xirsys.XTurn.Allocate.Client]},
      {Xirsys.XTurn.Auth.Supervisor, :start_link, []},
      {XSockets.SockSupervisor, :start_link, [[]]},
      {XSockets.TierSupervisor.Task, :start_link, [[]]},
      {XSockets.TierSupervisor.Pool, :start_link, [[]]}
    ] do
  case apply(elem(start, 0), elem(start, 1), elem(start, 2)) do
    {:ok, _} -> :ok
    {:error, {:already_started, _}} -> :ok
  end
end
