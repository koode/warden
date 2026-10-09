defmodule Warden.Integration.DenialTest do
  use ExUnit.Case, async: true

  defmodule Authz do
    @moduledoc false
    use Warden.Authorizer, roles: [:admin, :viewer], expose_denial_reasons: true

    def subject(ctx), do: ctx[:user]
    def roles(user, _), do: user.roles

    # The test picks the handler result through the context of the actor's subject.
    def deny(%Warden.Denial{actor: %{subject: %{deny: fun}}} = denial), do: fun.(denial)
    def deny(denial), do: Warden.Authorizer.default_deny(denial, __warden_catalog__())
  end

  defmodule Schema do
    @moduledoc false
    use Absinthe.Schema

    use Warden.Absinthe,
      authorizer: Warden.Integration.DenialTest.Authz,
      introspection: authenticated(),
      default_object_rule: role(:viewer)

    object :doc do
      field :id, :id
      field :title, :string
    end

    object :vault do
      authorize role(:admin)
      field :id, :id
    end

    query do
      field :salary, :string do
        authorize role(:admin)
        resolve fn _, _ -> {:ok, "1000"} end
      end

      field :required_salary, non_null(:string) do
        authorize role(:admin)
        resolve fn _, _ -> {:ok, "1000"} end
      end

      field :vault, :vault do
        authorize role(:admin)
        resolve fn _, _ -> {:ok, %{id: "v1"}} end
      end

      field :vaults, list_of(:vault) do
        resolve fn _, _ -> {:ok, [%{id: "v1"}, %{id: "v2"}]} end
      end

      field :filtered_vaults, list_of(:vault) do
        list_policy :filter
        resolve fn _, _ -> {:ok, [%{id: "v1"}, %{id: "v2"}]} end
      end

      field :doc, :doc do
        resolve fn _, _ -> {:ok, %{id: "d1", title: "T"}} end
      end

      field :search, :string do
        arg :deep, :boolean, default_value: false
        authorize_args deep: role(:admin)
        resolve fn _, _ -> {:ok, "results"} end
      end
    end
  end

  defp run(doc, user) do
    {:ok, result} = Absinthe.run(doc, Schema, context: %{user: user})
    result
  end

  defp user(roles, deny \\ nil) do
    base = %{id: "x", roles: roles}
    if deny, do: Map.put(base, :deny, deny), else: base
  end

  describe "{:error, term}" do
    test "a string, a map or a keyword list becomes the error" do
      for {term, expected} <- [
            {"Nope", %{message: "Nope"}},
            {%{message: "Nope", code: 403}, %{message: "Nope", code: 403}},
            {[message: "Nope", reason: "x"], %{message: "Nope", reason: "x"}}
          ] do
        result = run("{ salary }", user([], fn _ -> {:error, term} end))
        assert result.data == %{"salary" => nil}
        [error] = result.errors
        assert Map.take(error, Map.keys(expected)) == expected
      end
    end

    test "missing roles are only revealed when the authorizer opts in" do
      result = run("{ salary }", user([:viewer]))
      [error] = result.errors

      assert error.extensions == %{
               code: "FORBIDDEN",
               missing_roles: ["admin"],
               missing_permissions: []
             }
    end
  end

  describe ":null" do
    test "nulls the field without an error" do
      assert run("{ salary }", user([], fn _ -> :null end)) == %{data: %{"salary" => nil}}
    end

    test "on a non-null field Absinthe's non-null error still applies" do
      result = run("{ requiredSalary }", user([], fn _ -> :null end))
      assert result.data == nil
      assert [%{message: "Cannot return null for non-nullable field"}] = result.errors
    end

    test "on list items: nulls items without errors" do
      assert run("{ vaults { id } }", user([:viewer], fn _ -> :null end)) ==
               %{data: %{"vaults" => [nil, nil]}}
    end
  end

  describe "{:replace, value}" do
    test "replaces a denied field's value" do
      result = run("{ salary }", user([], fn _ -> {:replace, "hidden"} end))
      assert result == %{data: %{"salary" => "hidden"}}
    end

    test "object rules still apply to the replacement" do
      handler = fn
        %{kind: :field} -> {:replace, %{id: "fake"}}
        %{kind: :object} -> {:error, "object denied"}
      end

      result = run("{ vault { id } }", user([:viewer], handler))
      assert result.data == %{"vault" => nil}
      assert [%{message: "object denied"}] = result.errors
    end

    test "for an object denial it raises Warden.PolicyError" do
      assert_raise Warden.PolicyError, ~r/expected \{:error, term\} or :null/, fn ->
        run("{ vaults { id } }", user([:viewer], fn _ -> {:replace, %{id: "x"}} end))
      end
    end

    test "for an argument denial it raises Warden.PolicyError" do
      assert_raise Warden.PolicyError, fn ->
        run("{ search(deep: true) }", user([:viewer], fn _ -> {:replace, "x"} end))
      end
    end
  end

  test "an invalid handler result raises Warden.PolicyError" do
    for bad <- [:ok, nil, {:ok, "x"}, :error] do
      assert_raise Warden.PolicyError, fn -> run("{ salary }", user([], fn _ -> bad end)) end
    end
  end

  test "the denial carries kind, rule, path, field and value_index" do
    test_pid = self()

    handler = fn denial ->
      send(test_pid, {:denial, denial})
      {:error, "no"}
    end

    run("{ salary vaults { id } search(deep: true) }", user([:viewer], handler))

    denials =
      for _ <- 1..4 do
        assert_receive {:denial, d}
        d
      end

    salary = Enum.find(denials, &(&1.field == :salary))
    assert salary.kind == :field
    assert salary.rule == {:role, :admin}
    assert salary.failed_rule == {:role, :admin}
    assert salary.missing_roles == [:admin]
    assert salary.path == ["salary"]
    assert salary.parent_type == :query

    items = Enum.filter(denials, &(&1.field == :vaults))
    assert Enum.map(items, & &1.value_index) |> Enum.sort() == [[0], [1]]

    assert Enum.all?(
             items,
             &(&1.kind == :object and &1.type == :vault and &1.list_policy == :null_item)
           )

    search = Enum.find(denials, &(&1.field == :search))
    assert search.kind == :argument
    assert search.argument == [:deep]
  end

  test "items removed by :filter are passed to the handler with list_policy :filter" do
    test_pid = self()

    handler = fn denial ->
      send(test_pid, {:policy, denial.list_policy})
      Warden.Authorizer.default_deny(denial, Authz.__warden_catalog__())
    end

    assert run("{ filteredVaults { id } }", user([:viewer], handler)) ==
             %{data: %{"filteredVaults" => []}}

    assert_receive {:policy, :filter}
  end

  test "a :filter handler that returns an error nulls the item with that error" do
    result = run("{ filteredVaults { id } }", user([:viewer], fn _ -> {:error, "shown"} end))
    assert result.data == %{"filteredVaults" => [nil, nil]}

    assert result.errors |> Enum.map(& &1.path) |> Enum.sort() == [
             ["filteredVaults", 0],
             ["filteredVaults", 1]
           ]
  end

  describe "introspection guard" do
    test "__schema and __type follow the introspection rule" do
      result = run("{ __schema { queryType { name } } }", nil)
      assert result.data == %{"__schema" => nil}
      assert [%{message: "Forbidden"}] = result.errors

      result = run(~s|{ __type(name: "Vault") { name } }|, nil)
      assert result.data == %{"__type" => nil}

      assert run("{ __schema { queryType { name } } }", user([])).data ==
               %{"__schema" => %{"queryType" => %{"name" => "RootQueryType"}}}
    end

    test "__typename is never guarded" do
      assert run("{ __typename }", nil) == %{data: %{"__typename" => "RootQueryType"}}
    end
  end

  describe "default_object_rule" do
    test "applies to object types without their own rule" do
      assert run("{ doc { title } }", user([])).data == %{"doc" => nil}
      assert run("{ doc { title } }", user([:viewer])).data == %{"doc" => %{"title" => "T"}}
    end

    test "does not apply to root types" do
      assert run("{ __typename }", user([])).data == %{"__typename" => "RootQueryType"}
    end
  end
end
