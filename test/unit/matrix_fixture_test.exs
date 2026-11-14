defmodule Warden.Test.MatrixFixtureTest do
  # Fixture failures name the fixture and the line that declares it.
  use ExUnit.Case, async: true

  import Warden.Test.CompileHelpers

  alias Warden.Test.Matrix

  # A module with the fixture macros of `Warden.Test.Matrix` but without
  # `ExUnit.Case`, so its fixtures can be built inside this test. Returns the module and
  # the source, to find the declaring lines.
  defp fixtures!(body) do
    module = unique("Warden.Test.Compiled.Fixtures")

    code = """
    defmodule #{module}.Setup do
      defmacro register do
        Module.register_attribute(__CALLER__.module, :warden_matrix_fixtures, accumulate: true)
        :ok
      end
    end

    defmodule #{module} do
      require #{module}.Setup
      #{module}.Setup.register()
      import Warden.Test.Matrix, only: [actor: 2, resource: 2]

    #{body}

      def __warden_matrix__(:fixtures), do: Enum.reverse(@warden_matrix_fixtures)
    end
    """

    compile!(code)
    {Module.concat([module]), code}
  end

  defp line_of(code, text) do
    index = code |> String.split("\n") |> Enum.find_index(&String.contains?(&1, text))
    index + 1
  end

  @options %{authorizer: Warden.Test.Ecto.Authz, repo: Warden.Test.Repo, snapshot: "unused"}

  test "a fixture that raises names the fixture and its declaration" do
    {module, code} =
      fixtures!("""
        actor :owner, fn _context -> %{current_user: %{id: "abby"}} end
        actor :boom, fn _context -> raise ArgumentError, "fixture exploded" end
      """)

    line = line_of(code, "actor :boom")
    error = assert_raise ExUnit.AssertionError, fn -> Matrix.build(module, @options, %{}) end

    assert error.message ==
             "actor fixture :boom (nofile:#{line}) raised ArgumentError: fixture exploded"
  end

  test "a fixture that returns the wrong thing names the fixture and its declaration" do
    {module, code} = fixtures!("  resource :bad, fn _context -> :not_a_struct end")

    line = line_of(code, "resource :bad")
    error = assert_raise ExUnit.AssertionError, fn -> Matrix.build(module, @options, %{}) end
    assert error.message == "resource fixture :bad (nofile:#{line}) must return a struct"
  end
end
