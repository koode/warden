defmodule Warden.Test do
  @moduledoc """
  Test helpers that prove a policy gives one answer everywhere.

      test "the issue policy is consistent" do
        Warden.Test.assert_policy_consistent(
          MyApp.Authz.Issues,
          [owner: owner_context, guest: guest_context, webhook: webhook_actor],
          [public_issue: public_issue, private_issue: private_issue]
        )
      end

  `Warden.Test.Matrix` builds a whole matrix of actors and resources from fixtures and
  compares it with a snapshot; `Warden.Test.Absinthe.assert_matrix_matches/2` runs the
  same cells through GraphQL. The testing guide covers all three.

  Failures raise `ExUnit.AssertionError`. Messages name the actors, resources and
  actions, never a subject or row data. Nothing here loads ExUnit unless it is called.
  """

  alias Warden.Policy.Dispatch
  alias Warden.Rule
  alias Warden.Test.Cells

  @typedoc "Named values (`[name: value]`) or a plain list (named by position)."
  @type named(value) :: [{atom, value}] | [value]

  @typedoc "One cell: the actor's name, the row's name and the action."
  @type cell :: {atom | String.t(), atom | String.t(), atom}

  @doc """
  Asserts that for every actor, row and action of `policy`, every way Warden answers
  agrees, and returns `%{{actor_name, row_name, action} => allowed?}`.

  For a `Warden.Ecto.Policy` (needs `ecto`):

    * `Warden.Ecto.allowed?/4` on the struct (the policy's hand-written `allowed?/4`
      answers it when the policy defines one);
    * `Warden.Ecto.allowed?/4` on `{schema, id}`;
    * membership in `Repo.all(WardenEcto.scope(...))`;
    * membership in `Warden.Ecto.filter/4` over all the rows.

  For a `Warden.Policy`: `can(policy, action)` on the value alone and over the list
  (`Warden.allowed?/3` and `Warden.filter/4`).

  `actors` are actors or context maps; `rows` are structs of the policy's schema or
  `for:` module, persisted for an Ecto policy. Both may be named (`[owner: actor]`),
  else they are named by position (`"actor 1"`, `"row 2"`).

  Options: `:authorizer` (default: the policy's), `:repo` (default: the Ecto policy's
  `:repo`) and `:actions` (default: every action of the policy).
  """
  @spec assert_policy_consistent(module, named(term), named(struct), keyword) :: %{
          cell => boolean
        }
  def assert_policy_consistent(policy, actors, rows, opts \\ [])
      when is_list(actors) and is_list(rows) do
    info = Dispatch.info!(policy)
    authorizer = Keyword.get(opts, :authorizer, info.authorizer)
    actions = Keyword.get(opts, :actions, info.actions)
    actors = Cells.named(actors, "actor")
    rows = Cells.named(rows, "row")

    observations =
      for {actor_name, actor} <- actors, action <- actions do
        answers = observe(policy, action, actor, Enum.map(rows, &elem(&1, 1)), authorizer, opts)
        {actor_name, action, answers}
      end

    cells =
      for {actor_name, action, answers} <- observations,
          {{row_name, _row}, answer} <- Enum.zip(rows, answers),
          into: %{},
          do: {{actor_name, row_name, action}, answer}

    case disagreements(observations, rows) do
      [] -> Map.new(cells, fn {cell, answer} -> {cell, decided(answer)} end)
      problems -> fail!(policy, problems)
    end
  end

  defp observe_core(policy, action, actor, rows, authorizer) do
    rule = Rule.can(policy, action)
    filtered = Warden.filter(actor, rule, rows, authorizer: authorizer)
    kept = kept(rows, filtered)

    rows
    |> Enum.zip(kept)
    |> Enum.map(fn {row, in_list?} ->
      single = Warden.allowed?(actor, rule, value: row, authorizer: authorizer)
      [{"can/2 on the value", single}, {"can/2 over the list", in_list?}]
    end)
  end

  # One answer per row: `[{source, allowed?}]` for every way of asking. Without Ecto
  # there are no Ecto policies.
  if Code.ensure_loaded?(Ecto) do
    alias Warden.Ecto, as: WardenEcto
    alias Warden.Ecto.Info

    defp observe(policy, action, actor, rows, authorizer, opts) do
      if Info.ecto_policy?(policy),
        do: observe_ecto(policy, action, actor, rows, authorizer, opts),
        else: observe_core(policy, action, actor, rows, authorizer)
    end

    defp observe_ecto(policy, action, actor, rows, authorizer, opts) do
      info = Info.fetch!(policy)
      repo = Keyword.get(opts, :repo) || Info.repo!(info)
      call_opts = [authorizer: authorizer]
      key = info.primary_key

      struct_label =
        if info.allowed? or info.allowed_many?,
          do: "allowed?/4 (hand-written)",
          else: "allowed?/3"

      scoped = info.schema |> WardenEcto.scope(actor, action, call_opts) |> ecto_keys(repo, key)
      kept = kept(rows, WardenEcto.filter(actor, action, rows, call_opts))

      rows
      |> Enum.zip(kept)
      |> Enum.map(fn {row, in_list?} ->
        id = Map.fetch!(row, key)

        [
          {struct_label, WardenEcto.allowed?(actor, action, row, call_opts)},
          {"allowed?/3 by id", WardenEcto.allowed?(actor, action, {info.schema, id}, call_opts)},
          {"scope/4", MapSet.member?(scoped, id)},
          {"filter/3", in_list?}
        ]
      end)
    end

    defp ecto_keys(query, repo, key) do
      import Ecto.Query, only: [select: 3]

      keys_query = select(query, [row], field(row, ^key))
      keys_query |> repo.all() |> MapSet.new()
    end
  else
    defp observe(policy, action, actor, rows, authorizer, _opts),
      do: observe_core(policy, action, actor, rows, authorizer)
  end

  # `filter` keeps order and duplicates, so the kept rows are found by walking both lists.
  defp kept([], _filtered), do: []
  defp kept([row | rows], [row | filtered]), do: [true | kept(rows, filtered)]
  defp kept([_row | rows], filtered), do: [false | kept(rows, filtered)]

  defp decided([{_source, allowed?} | _others]), do: allowed?

  defp disagreements(observations, rows) do
    for {actor_name, action, answers} <- observations,
        {{row_name, _row}, answer} <- Enum.zip(rows, answers),
        answer |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length() > 1 do
      {{actor_name, row_name, action}, answer}
    end
  end

  @spec fail!(module, list) :: no_return()
  defp fail!(policy, problems) do
    count = length(problems)

    lines =
      Enum.map_join(problems, "\n", fn {cell, answer} -> "  " <> Cells.describe(cell, answer) end)

    message = """
    #{inspect(policy)} gives different answers in #{count} cell(s):
    #{lines}\
    """

    raise ExUnit.AssertionError, message: message
  end
end
