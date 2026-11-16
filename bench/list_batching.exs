# Measures what Warden's Absinthe middleware costs on a large list: 100 items with 80
# fields each, every item under one of 10 shared teams (the same Team term under ten
# items, as Dataloader and Ecto preloads hand it out).
#
#     mix run bench/list_batching.exs
#
# For each object rule it reports the authorizer calls (`check/2`, `check_many/2` and
# policy calls), the Warden decision events, the reductions of the process that runs the
# document and the median wall time. BENCH_RUNS sets the measured runs (default 20).
# BENCH_REUSE=0 compiles the schemas with `decision_reuse: false`, and BENCH_PER_OBJECT=0
# leaves `per_object: true` off the checks: together they decide as 0.3.0 did.

reuse? = System.get_env("BENCH_REUSE", "1") == "1"
per_object? = System.get_env("BENCH_PER_OBJECT", "1") == "1"
runs = String.to_integer(System.get_env("BENCH_RUNS", "20"))
item_count = 100
team_count = 10
scalar_count = 78

defmodule Bench.Counter do
  @moduledoc false
  def bump(key), do: Process.put({__MODULE__, key}, Process.get({__MODULE__, key}, 0) + 1)

  def decision(_event, _measurements, _metadata, _config), do: bump(:decision)

  def take(key) do
    count = Process.get({__MODULE__, key}, 0)
    Process.put({__MODULE__, key}, 0)
    count
  end
end

scalar_fields = Enum.map(1..scalar_count, &:"f#{&1}")

defmodule Bench.Team do
  @moduledoc false
  defstruct [:id, :name, :key, :color, :workspace_id]
end

Code.eval_quoted(
  quote do
    defmodule Bench.Item do
      @moduledoc false
      defstruct [:id, :team_id, :team | unquote(scalar_fields)]
    end
  end
)

check_spec = if per_object?, do: [per_object: true], else: []

Code.eval_quoted(
  quote do
    defmodule Bench.Authz do
      @moduledoc false
      use Warden.Authorizer,
        roles: [:member],
        policies: [Bench.TeamPolicy],
        checks: [in_team: unquote(check_spec), team_visible: unquote(check_spec)]

      @impl true
      def subject(context), do: context[:current_user]

      @impl true
      def roles(_user, _context), do: [:member]

      @impl true
      def check(:in_team, %Warden.Check{actor: actor, value: value}) do
        Bench.Counter.bump(:authorizer)
        value.team_id in actor.subject.team_ids
      end

      def check(:team_visible, %Warden.Check{actor: actor, value: value}) do
        Bench.Counter.bump(:authorizer)
        value.id in actor.subject.team_ids
      end
    end
  end
)

defmodule Bench.TeamPolicy do
  @moduledoc false
  use Warden.Policy, authorizer: Bench.Authz, for: Bench.Team, actions: [:read]

  @impl true
  def allowed?(:read, actor, %Bench.Team{} = team, _context) do
    Bench.Counter.bump(:authorizer)
    team.id in actor.subject.team_ids
  end
end

schema_options = if reuse?, do: "", else: ", decision_reuse: false"

rules = [
  {"check (custom, per object)", "check(:in_team)", "check(:team_visible)"},
  {"role (built in)", "role(:member)", "role(:member)"},
  {"can (policy)", "role(:member)", "can(Bench.TeamPolicy, :read)"},
  {"no Warden (floor)", nil, nil}
]

scalar_source = Enum.map_join(scalar_fields, "\n", &"    field #{inspect(&1)}, :string")

schemas =
  rules
  |> Enum.with_index()
  |> Enum.map(fn {{label, item_rule, team_rule}, index} ->
    module = "Bench.Schema#{index}"
    warden? = item_rule != nil
    use_warden = if warden?, do: "use Warden.Absinthe, authorizer: Bench.Authz#{schema_options}", else: ""
    team_authorize = if warden?, do: "authorize #{team_rule}", else: ""
    item_authorize = if warden?, do: "authorize #{item_rule}", else: ""
    flagged_authorize = if warden?, do: "authorize role(:member)", else: ""

    source = """
    defmodule #{module} do
      use Absinthe.Schema
      #{use_warden}

      object :team do
        #{team_authorize}
        field :id, :id
        field :name, :string
        field :key, :string
        field :color, :string
      end

      object :item do
        #{item_authorize}
        field :id, :id
        field :team, :team
        field :flagged, :string do
          #{flagged_authorize}
          resolve fn item, _args, _resolution -> {:ok, item.f1} end
        end
    #{scalar_source}
      end

      query do
        field :items, list_of(:item) do
          resolve fn _args, resolution -> {:ok, resolution.context.items} end
        end
      end
    end
    """

    [{schema, _bytecode} | _rest] = Code.compile_string(source)
    {label, schema}
  end)

teams =
  Enum.map(1..team_count, fn index ->
    struct!(Bench.Team, id: "t#{index}", name: "Team #{index}", key: "T#{index}", color: "#fff")
  end)

items =
  Enum.map(1..item_count, fn index ->
    team = Enum.at(teams, rem(index, team_count))
    scalars = Map.new(scalar_fields, &{&1, "value #{index}"})
    struct!(Bench.Item, Map.merge(scalars, %{id: index, team_id: team.id, team: team}))
  end)

user = %{id: "u1", team_ids: Enum.map(teams, & &1.id)}
context = %{current_user: user, items: items}

document = """
{ items { id flagged #{Enum.map_join(scalar_fields, " ", &to_string/1)} team { id name key color } } }
"""

:telemetry.attach(
  "bench-decisions",
  [:warden, :decision],
  &Bench.Counter.decision/4,
  nil
)

IO.puts("decision_reuse: #{reuse?}, per_object: #{per_object?}, runs: #{runs}")
IO.puts("object rule | authorizer calls | decision events | reductions | median wall us")

for {label, schema} <- schemas do
  for _warmup <- 1..3, do: {:ok, _result} = Absinthe.run(document, schema, context: context)
  Bench.Counter.take(:authorizer)
  Bench.Counter.take(:decision)

  samples =
    Enum.map(1..runs, fn _run ->
      {:reductions, before} = Process.info(self(), :reductions)
      started = System.monotonic_time(:microsecond)
      {:ok, %{data: %{"items" => [_ | _]}}} = Absinthe.run(document, schema, context: context)
      wall = System.monotonic_time(:microsecond) - started
      {:reductions, after_run} = Process.info(self(), :reductions)
      {after_run - before, wall}
    end)

  calls = div(Bench.Counter.take(:authorizer), runs)
  decisions = div(Bench.Counter.take(:decision), runs)
  reductions = samples |> Enum.map(&elem(&1, 0)) |> Enum.sort() |> Enum.at(div(runs, 2))
  wall = samples |> Enum.map(&elem(&1, 1)) |> Enum.sort() |> Enum.at(div(runs, 2))
  IO.puts("#{label} | #{calls} | #{decisions} | #{reductions} | #{wall}")
end
