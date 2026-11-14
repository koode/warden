defmodule Warden.Adversarial.AdmissionPathsTest do
  @moduledoc """
  Admissions (values the post middleware decided under a batched object rule, whose
  fields then skip that rule) are keyed by type and response path. These attacks try to
  make a path name another value than the one that was decided: `:filter` shifting the
  output indexes, and middleware that replaces the value after the resolver.
  """
  use ExUnit.Case, async: true

  import Warden.Test.RedteamV2.People

  alias Warden.Test.RedteamV2.Ticket

  defmodule Swap do
    @moduledoc false
    # Replaces the resolved list with the one in its options, after the resolver.
    @behaviour Absinthe.Middleware

    @impl true
    def call(resolution, replacement),
      do: Absinthe.Resolution.put_result(resolution, {:ok, replacement})
  end

  defmodule Schema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Absinthe, authorizer: Warden.Test.RedteamV2.Authz

    object :ticket do
      authorize check(:live)
      field :id, :integer
      field :secret, :string
    end

    query do
      field :filtered, list_of(:ticket) do
        list_policy :filter
        resolve fn _args, resolution -> {:ok, resolution.context.entries} end
      end

      field :nested, list_of(list_of(:ticket)) do
        list_policy :filter
        resolve fn _args, resolution -> {:ok, resolution.context.rows} end
      end

      field :swapped, list_of(:ticket) do
        resolve fn _args, resolution ->
          {:middleware, Swap, resolution.context.replacement}
        end
      end
    end
  end

  defp ticket(id, visible?), do: %Ticket{id: id, visible: visible?, secret: "secret #{id}"}

  defp batched_calls do
    receive do
      {:check_many, :live, _count} -> 1 + batched_calls()
    after
      0 -> 0
    end
  end

  test ":filter shifts output indexes; every shown value is the decided one, with one call" do
    entries = [ticket(1, false), ticket(2, true), ticket(3, false), ticket(4, true)]

    result = run(Schema, "{ filtered { id secret } }", abby(), %{entries: entries})

    assert result.data == %{
             "filtered" => [
               %{"id" => 2, "secret" => "secret 2"},
               %{"id" => 4, "secret" => "secret 4"}
             ]
           }

    # Keyed by input position, the fields of the second shown value (input 3, output 1)
    # would find no admission and decide again; keyed by output position they find it.
    assert batched_calls() == 1
  end

  test "nested lists under :filter keep every output position right" do
    rows = [
      [ticket(1, false), ticket(2, true)],
      [ticket(3, true), ticket(4, false), ticket(5, true)]
    ]

    result = run(Schema, "{ nested { id secret } }", abby(), %{rows: rows})

    assert result.data == %{
             "nested" => [
               [%{"id" => 2, "secret" => "secret 2"}],
               [%{"id" => 3, "secret" => "secret 3"}, %{"id" => 5, "secret" => "secret 5"}]
             ]
           }

    refute inspect(result) =~ "secret 1"
    refute inspect(result) =~ "secret 4"
  end

  test "a value replaced after the resolver is decided as replaced, never admitted as before" do
    replacement = [ticket(7, false), ticket(8, true)]

    result = run(Schema, "{ swapped { id secret } }", abby(), %{replacement: replacement})

    assert result.data == %{"swapped" => [nil, %{"id" => 8, "secret" => "secret 8"}]}
    refute inspect(result) =~ "secret 7"
  end
end
