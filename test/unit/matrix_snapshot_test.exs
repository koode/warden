defmodule Warden.Test.MatrixSnapshotTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Warden.Matrix, as: MatrixTask
  alias Warden.Test.Matrix.Snapshot

  @model %{
    policies: [
      {Zeta.Policy, [:write, :read], [:zeta_row]},
      {Alpha.Policy, [:read], [:b_row, :a_row]}
    ],
    actors: [:owner, :guest],
    allowed: %{
      {:a_row, :owner} => [:read],
      {:zeta_row, :owner} => [:write, :read],
      {:b_row, :guest} => [:read]
    },
    redacted: %{{:b_row, :guest} => [:body, :anchor]}
  }

  test "renders sorted policies, resources, actors and actions" do
    table = Snapshot.render(@model)

    assert table =~ """
           policy Alpha.Policy
           actions read
           resource  guest  owner
           a_row     -      read
           b_row     read   -

           policy Zeta.Policy
           actions read write
           resource  guest  owner
           zeta_row  -      read,write

           redacted
           resource  actor  fields
           b_row     guest  anchor,body
           """

    shuffled = %{@model | actors: [:guest, :owner], policies: Enum.reverse(@model.policies)}
    assert Snapshot.render(shuffled) == table
  end

  test "parses back into cells, and the diff names changed cells only" do
    table = Snapshot.render(@model)
    cells = Snapshot.cells(table)

    assert cells[{:cell, "a_row", "owner"}] == "read"
    assert cells[{:cell, "zeta_row", "guest"}] == "-"
    assert cells[{:actions, "Zeta.Policy"}] == "read write"
    assert cells[{:redacted, "b_row", "guest"}] == "anchor,body"

    changed = %{
      @model
      | allowed: Map.put(@model.allowed, {:a_row, :guest}, [:read]),
        redacted: %{}
    }

    diff = Snapshot.diff(cells, Snapshot.cells(Snapshot.render(changed)))

    assert diff == [
             "resource a_row, actor guest: snapshot -, now read",
             "resource b_row, actor guest redacted fields: snapshot anchor,body, now none"
           ]
  end

  test "a layout-only difference has no changed cells" do
    table = Snapshot.render(@model)
    relaid = String.replace(table, "  ", "      ")
    assert Snapshot.diff(Snapshot.cells(table), Snapshot.cells(relaid)) == []
  end

  test "mix warden.matrix runs the tagged matrix tests in print or update mode" do
    assert MatrixTask.command([]) ==
             {"mix", ["test", "--only", "warden_matrix"],
              [{"MIX_ENV", "test"}, {"WARDEN_MATRIX", "print"}]}

    assert MatrixTask.command(["--update", "test/authz"]) ==
             {"mix", ["test", "--only", "warden_matrix", "test/authz"],
              [{"MIX_ENV", "test"}, {"WARDEN_MATRIX", "update"}]}
  end
end
