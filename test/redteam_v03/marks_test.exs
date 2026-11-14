defmodule Warden.RedteamV03.MarksTest do
  # Rows loaded with `Warden.Ecto.all/5` carry a mark that later decisions trust. Every
  # test asserts the secure behaviour: a failing test is an open hole.
  use Warden.Test.EctoCase, async: true

  alias Warden.Ecto, as: WardenEcto
  alias Warden.Ecto.Mark
  alias Warden.Test.Ecto.{Project, Projects}

  # `Projects` requires `check(:active)`, which reads `context.active`: the same actor is
  # allowed under `active: true` and denied under `active: false`.
  setup do
    project = insert!(%Project{workspace_id: "t1", name: "roadmap"})
    %{project: project}
  end

  defp read_rule, do: Warden.Rule.can(Projects, :read)

  defp load(actor, opts \\ []) do
    query = from(project in Project, order_by: project.id)
    WardenEcto.all(Repo, query, actor, :read, opts)
  end

  # Goal 8: a decision about a loaded struct must match the policy. The mark names the
  # policy, action, actor instance, prefix and fields, but not the context the scope ran
  # with, so a later decision under a context the policy denies still allows the row.
  describe "the context a mark was made under" do
    test "a decision under another context is the policy's, not the mark's" do
      actor = actor(sam(), %{active: true})
      [row] = load(actor)
      inactive = %{active: false, current_user: sam()}

      # The policy's own answer for this context.
      refute WardenEcto.allowed?(actor, :read, Mark.unmark(row), context: inactive)
      assert WardenEcto.filter(actor, :read, [Mark.unmark(row)], context: inactive) == []

      refute WardenEcto.allowed?(actor, :read, row, context: inactive)
      assert WardenEcto.filter(actor, :read, [row], context: inactive) == []
      assert WardenEcto.explain(actor, :read, row, context: inactive).result == :deny
    end

    test "rows loaded with an explicit context are not trusted under the actor's own" do
      actor = actor(sam(), %{active: false})
      assert load(actor) == []

      [row] = load(actor, context: %{active: true, current_user: sam()})

      refute WardenEcto.allowed?(actor, :read, row)
      assert Warden.filter(actor, read_rule(), [row]) == []
    end
  end

  describe "query shapes" do
    test "a union is refused, so its other arm is never marked" do
      actor = actor(sam())
      other_arm = from(project in Project, where: project.workspace_id == "t2")
      query = from(project in Project, union_all: ^other_arm)

      assert_raise ArgumentError, ~r/union/, fn -> WardenEcto.all(Repo, query, actor, :read) end
    end

    test "rows of another tenant pulled in by a subquery condition are still scoped" do
      insert!(%Project{workspace_id: "t2", name: "elsewhere"})
      actor = actor(sam())
      foreign = from(project in Project, where: project.workspace_id == "t2", select: project.id)
      query = from(project in Project, or_where: project.id in subquery(foreign))

      rows = load_query(actor, query)
      assert Enum.all?(rows, &(&1.workspace_id == "t1"))
    end

    test "a distinct or group_by query marks only scoped rows" do
      insert!(%Project{workspace_id: "t2", name: "elsewhere"})
      actor = actor(sam())
      query = from(project in Project, distinct: project.name, group_by: project.id)

      rows = load_query(actor, query)
      assert Enum.map(rows, & &1.workspace_id) == ["t1"]
    end
  end

  defp load_query(actor, query), do: WardenEcto.all(Repo, query, actor, :read)

  describe "rows used after loading" do
    test "a mark sent to another process is trusted only by the loading actor" do
      actor = actor(sam())
      [row] = load(actor)
      copied = :erlang.binary_to_term(:erlang.term_to_binary(row))
      outsider = actor(kim())

      refute WardenEcto.allowed?(outsider, :read, copied)
      assert WardenEcto.allowed?(actor, :read, copied)
    end
  end
end
