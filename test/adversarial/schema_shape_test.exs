defmodule Warden.Adversarial.SchemaShapeTest do
  @moduledoc """
  Attempts to lose rules or middleware through the way a schema is built.
  """
  use ExUnit.Case, async: true

  import Warden.Test.Helpers

  defmodule StateIgnoring do
    @moduledoc false
    # A user middleware that performs a side effect whatever the resolution state.
    @behaviour Absinthe.Middleware
    def call(res, _) do
      if pid = res.context[:test_pid], do: send(pid, {:resolved, :state_ignoring})
      res
    end
  end

  defmodule Types do
    @moduledoc false
    use Absinthe.Schema.Notation
    use Warden.Absinthe.Notation

    object :shared_fields do
      field :salary, :string do
        authorize role(:admin)
        resolve fn _, _, _ -> {:ok, "1000"} end
      end
    end

    object :imported_secret do
      authorize role(:admin)
      field :code, :string
    end
  end

  defmodule Schema do
    @moduledoc false
    use Absinthe.Schema
    use Warden.Absinthe, authorizer: Warden.Test.Authz

    import_types Types

    def middleware(middleware, %{identifier: :guarded}, _) do
      middleware ++ [StateIgnoring]
    end

    def middleware(middleware, _, _), do: middleware

    object :person do
      field :name, :string
    end

    extend object(:person) do
      field :ssn, :string do
        authorize role(:admin)
      end
    end

    query do
      import_fields :shared_fields

      field :imported_secret, :imported_secret do
        resolve fn _, _, _ -> {:ok, %{code: "ALPHA"}} end
      end

      field :person, :person do
        resolve fn _, _, _ -> {:ok, %{name: "P", ssn: "123"}} end
      end

      field :guarded, :string do
        authorize role(:admin)
        resolve fn _, _, _ -> {:ok, "x"} end
      end
    end
  end

  defmodule PTSchema do
    @moduledoc false
    use Absinthe.Schema
    @schema_provider Absinthe.Schema.PersistentTerm
    use Warden.Absinthe, authorizer: Warden.Test.Authz

    object :secret do
      authorize role(:admin)
      field :code, :string
    end

    query do
      field :secret, :secret do
        resolve fn _, _, _ -> {:ok, %{code: "ALPHA"}} end
      end

      field :salary, :string do
        authorize role(:admin)
        resolve fn _, _, _ -> {:ok, "1000"} end
      end
    end
  end

  test "rules on fields pulled in with import_fields" do
    assert run("{ salary }", viewer(), schema: Schema).data == %{"salary" => nil}
    assert run("{ salary }", admin(), schema: Schema).data == %{"salary" => "1000"}
  end

  test "object rules on types from import_types" do
    assert run("{ importedSecret { code } }", viewer(), schema: Schema).data == %{
             "importedSecret" => nil
           }
  end

  test "rules on fields added with extend object" do
    assert run("{ person { name ssn } }", viewer(), schema: Schema).data ==
             %{"person" => %{"name" => "P", "ssn" => nil}}
  end

  test "user middleware that ignores the resolution state does not run after a denial" do
    assert run("{ guarded }", viewer(), schema: Schema).data == %{"guarded" => nil}
    assert resolved() == []

    assert run("{ guarded }", admin(), schema: Schema).data == %{"guarded" => "x"}
    assert resolved() == [:state_ignoring]
  end

  test "the persistent_term schema provider" do
    assert run("{ secret { code } salary }", viewer(), schema: PTSchema).data ==
             %{"secret" => nil, "salary" => nil}

    assert run("{ secret { code } salary }", admin(), schema: PTSchema).data ==
             %{"secret" => %{"code" => "ALPHA"}, "salary" => "1000"}
  end
end
