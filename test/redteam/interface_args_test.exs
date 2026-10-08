defmodule Warden.Redteam.InterfaceArgsTest do
  @moduledoc """
  Red team, schema-shape lens: argument rules declared on interface fields when the
  implementing object's field declares the argument differently (or not at all).
  Absinthe validates documents against the interface field when selecting through the
  interface, then runs the concrete object's field with the coerced arguments.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers
  import Warden.Test.CompileHelpers

  @authz "authorizer: Warden.Redteam.Authz"

  test "interface argument rule when the implementing field omits the argument" do
    body = """
    interface :listing do
      field :items, list_of(:string) do
        arg :include_hidden, :boolean, default_value: false
        authorize_args include_hidden: role(:admin)
      end

      resolve_type fn _, _ -> :shelf end
    end

    object :shelf do
      interfaces [:listing]

      field :items, list_of(:string) do
        resolve fn _, args, %{context: %{test_pid: pid}} ->
          send(pid, {:resolved, {:items, args}})
          if args[:include_hidden], do: {:ok, ["HIDDEN"]}, else: {:ok, ["shown"]}
        end
      end
    end

    query do
      field :listing, :listing, resolve: fn _, _ -> {:ok, %{}} end
    end
    """

    schema = compile_schema(body, @authz)
    r = run(~s|{ listing { items(includeHidden: true) } }|, viewer(), schema: schema)
    refute contains?(Map.get(r, :data), "HIDDEN")
    refute_received {:resolved, {:items, %{include_hidden: true}}}
  end

  test "interface argument rule when the implementing field has a different default" do
    body = """
    interface :listing do
      field :items, list_of(:string) do
        arg :include_hidden, :boolean, default_value: false
        authorize_args include_hidden: role(:admin)
      end

      resolve_type fn _, _ -> :shelf end
    end

    object :shelf do
      interfaces [:listing]

      field :items, list_of(:string) do
        arg :include_hidden, :boolean, default_value: true

        resolve fn _, args, _ ->
          if args[:include_hidden], do: {:ok, ["HIDDEN"]}, else: {:ok, ["shown"]}
        end
      end
    end

    query do
      field :listing, :listing, resolve: fn _, _ -> {:ok, %{}} end
    end
    """

    schema = compile_schema(body, @authz)
    # The client selects through the interface, whose default (false) is what it sees.
    r = run(~s|{ listing { items(includeHidden: true) } }|, viewer(), schema: schema)
    refute contains?(Map.get(r, :data), "HIDDEN")
  end

  test "interface input-object argument whose implementing field types the argument differently" do
    body = """
    input_object :opts do
      field :reveal, :boolean do
        authorize role(:admin)
      end
    end

    input_object :loose_opts do
      field :reveal, :boolean
    end

    interface :listing do
      field :items, list_of(:string) do
        arg :opts, :opts
      end

      resolve_type fn _, _ -> :shelf end
    end

    object :shelf do
      interfaces [:listing]

      field :items, list_of(:string) do
        arg :opts, :loose_opts

        resolve fn _, args, _ ->
          if get_in(args, [:opts, :reveal]), do: {:ok, ["HIDDEN"]}, else: {:ok, ["shown"]}
        end
      end
    end

    query do
      field :listing, :listing, resolve: fn _, _ -> {:ok, %{}} end
    end
    """

    schema = compile_schema(body, @authz)
    r = run(~s|{ listing { items(opts: {reveal: true}) } }|, viewer(), schema: schema)
    refute contains?(Map.get(r, :data), "HIDDEN")
  end
end
