defmodule Warden.Test.CompileHelpers do
  @moduledoc false

  @doc "Compiles a schema module with the given body. Returns the module."
  def compile_schema(body, opts \\ "authorizer: Warden.Test.Authz") do
    name = "Warden.Test.Compiled.S#{System.unique_integer([:positive])}"

    code = """
    defmodule #{name} do
      use Absinthe.Schema
      use Warden.Schema, #{opts}

    #{body}
    end
    """

    compile!(code)
    Module.concat([name])
  end

  def compile!(code) do
    ExUnit.CaptureIO.capture_io(:stderr, fn ->
      send(self(), {:compiled, Code.compile_string(code)})
    end)

    receive do
      {:compiled, mods} -> mods
    end
  end

  def unique(prefix), do: "#{prefix}#{System.unique_integer([:positive])}"
end
