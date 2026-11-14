defmodule Warden.Test.EctoCase do
  @moduledoc false
  # A test case for the `:postgres` suite: every test runs in a sandbox transaction.
  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL.Sandbox
  alias Warden.Test.Repo

  using do
    quote do
      @moduletag :postgres

      import Ecto.Query
      import Warden.Test.EctoCase
      import Warden.Test.Ecto.People

      alias Warden.Test.Repo
    end
  end

  setup tags do
    pid = Sandbox.start_owner!(Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end

  @doc "Inserts a struct and returns it."
  def insert!(struct), do: Repo.insert!(struct)

  @doc "The ids of a list of structs, in order."
  def ids(structs), do: Enum.map(structs, & &1.id)

  @doc "The ids that a query returns, sorted."
  def all_ids(query) do
    query
    |> Repo.all()
    |> Enum.map(& &1.id)
    |> Enum.sort()
  end

  @doc """
  Counts the repo queries that `fun` runs in this process, from Ecto's telemetry.
  Returns `{result, count}`.
  """
  def count_queries(fun) do
    handler = "warden-queries-#{System.unique_integer([:positive])}"
    test_pid = self()

    :ok =
      :telemetry.attach(
        handler,
        [:warden, :test, :repo, :query],
        fn _event, _measure, _meta, _config ->
          if self() == test_pid, do: send(test_pid, {:repo_query, handler})
        end,
        nil
      )

    try do
      result = fun.()
      {result, drain(handler, 0)}
    after
      :telemetry.detach(handler)
    end
  end

  defp drain(handler, count) do
    receive do
      {:repo_query, ^handler} -> drain(handler, count + 1)
    after
      0 -> count
    end
  end
end
