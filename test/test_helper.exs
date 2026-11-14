{:ok, _} = Registry.start_link(keys: :duplicate, name: Warden.Test.Pubsub.Topics)
{:ok, _} = Supervisor.start_link([Warden.Test.Pubsub], strategy: :one_for_one)

# The `:postgres` suite needs a database: run it with `mix test --only postgres`
# (WARDEN_DATABASE_URL, default postgres://localhost/warden_test). The database is created
# here and dropped when the suite ends.
postgres? =
  Enum.any?(ExUnit.configuration()[:include] || [], fn
    :postgres -> true
    {:postgres, _value} -> true
    _other -> false
  end)

if postgres? do
  Warden.Test.Database.setup!()
  ExUnit.after_suite(fn _result -> Warden.Test.Database.teardown!() end)
end

ExUnit.start(capture_log: true, exclude: [:no_optional_deps, :postgres])
