{:ok, _} = Registry.start_link(keys: :duplicate, name: Warden.Test.Pubsub.Topics)
{:ok, _} = Supervisor.start_link([Warden.Test.Pubsub], strategy: :one_for_one)

ExUnit.start(capture_log: true)
