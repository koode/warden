defmodule Warden.Standalone.NoOptionalDepsTest do
  @moduledoc """
  Builds throwaway Mix projects that depend on Warden by path, with and without the
  optional dependencies, compiles them with warnings as errors and runs Warden in them.

  Excluded by default (it builds whole projects). Run it with:

      mise exec -- mix test --only no_optional_deps

  The plug-only and absinthe-only projects fetch those packages from Hex (the local Hex
  cache is used when it has them).
  """
  use ExUnit.Case, async: false

  @moduletag :no_optional_deps
  @moduletag timeout: 900_000

  @repo Path.expand("../..", __DIR__)

  @authorizer """
  defmodule Standalone.Authz do
    use Warden.Authorizer, roles: [:admin, :viewer]

    @impl true
    def subject(context), do: context[:current_user]

    @impl true
    def roles(user, _context), do: user.roles
  end
  """

  defp project(name, extra_deps, files) do
    dir = Path.join(System.tmp_dir!(), "warden_#{name}_#{System.unique_integer([:positive])}")
    File.rm_rf!(dir)
    File.mkdir_p!(Path.join(dir, "lib"))
    File.mkdir_p!(Path.join(dir, "config"))

    File.write!(Path.join(dir, "mix.exs"), """
    defmodule Standalone.MixProject do
      use Mix.Project

      def project do
        [app: :standalone, version: "0.1.0", elixir: "~> 1.14", deps: deps()]
      end

      def application, do: [extra_applications: [:logger]]

      defp deps do
        [{:warden, path: #{inspect(@repo)}} | #{extra_deps}]
      end
    end
    """)

    Enum.each(files, fn {path, content} -> File.write!(Path.join(dir, path), content) end)

    unless Map.has_key?(files, "config/config.exs") do
      File.write!(Path.join(dir, "config/config.exs"), "import Config\n")
    end

    on_exit(fn -> File.rm_rf!(dir) end)
    dir
  end

  defp mix!(dir, args) do
    env = [
      {"MIX_ENV", "dev"},
      {"MIX_DEPS_PATH", nil},
      {"MIX_BUILD_ROOT", nil},
      {"MIX_BUILD_PATH", nil},
      {"MIX_LOCKFILE", nil}
    ]

    {output, status} = System.cmd("mix", args, cd: dir, env: env, stderr_to_stdout: true)
    assert status == 0, "mix #{Enum.join(args, " ")} failed in #{dir}:\n#{output}"
    output
  end

  # Fetches and compiles the deps, asserts Warden compiled without a single warning,
  # then compiles the project itself with --warnings-as-errors.
  defp build!(dir) do
    mix!(dir, ["deps.get"])
    output = mix!(dir, ["deps.compile"])

    warden_section =
      output
      |> String.split("==> ")
      |> Enum.filter(&String.starts_with?(&1, "warden"))
      |> Enum.join()

    assert warden_section =~ "Generated warden app", output
    refute warden_section =~ "warning", warden_section

    mix!(dir, ["compile", "--warnings-as-errors"])
  end

  defp run!(dir, code), do: mix!(dir, ["run", "-e", code])

  @check_core """
  import Warden.Rule
  admin = %{current_user: %{id: "u1", roles: [:admin]}}
  viewer = %{current_user: %{id: "u2", roles: [:viewer]}}
  IO.puts("authorize=" <> inspect(Warden.authorize(admin, role(:admin), AUTHZ)))
  {:error, %Warden.Denial{kind: :call}} = Warden.authorize(viewer, role(:admin), AUTHZ)
  IO.puts("filter=" <> inspect(Warden.filter(viewer, role(:viewer), [1, 2], AUTHZ)))
  IO.puts("absinthe=" <> inspect(Code.ensure_loaded?(Warden.Absinthe)))
  IO.puts("plug=" <> inspect(Code.ensure_loaded?(Warden.Plug)))
  """

  test "neither absinthe nor plug: explicit authorizer" do
    dir = project("core_explicit", "[]", %{"lib/authz.ex" => @authorizer})
    build!(dir)
    out = run!(dir, String.replace(@check_core, "AUTHZ", "authorizer: Standalone.Authz"))

    assert out =~ "authorize=:ok"
    assert out =~ "filter=[1, 2]"
    assert out =~ "absinthe=false"
    assert out =~ "plug=false"
  end

  test "neither absinthe nor plug: only the configured default authorizer" do
    dir =
      project("core_default", "[]", %{
        "lib/authz.ex" => @authorizer,
        "config/config.exs" => "import Config\nconfig :warden, authorizer: Standalone.Authz\n"
      })

    build!(dir)
    out = run!(dir, String.replace(@check_core, ", AUTHZ", ""))

    assert out =~ "authorize=:ok"
    assert out =~ "filter=[1, 2]"
    assert out =~ "absinthe=false"
  end

  test "plug without absinthe" do
    dir =
      project("plug_only", ~s([{:plug, "~> 1.14"}]), %{
        "lib/authz.ex" => @authorizer,
        "config/config.exs" => "import Config\nconfig :warden, authorizer: Standalone.Authz\n"
      })

    build!(dir)

    out =
      run!(dir, """
      import Warden.Rule
      opts = Warden.Plug.init(rule: role(:admin))
      conn = Plug.Test.conn(:get, "/") |> Plug.Conn.assign(:current_user, %{id: "u2", roles: [:viewer]})
      conn = Warden.Plug.call(conn, opts)
      IO.puts("status=" <> inspect({conn.status, conn.halted}))
      IO.puts("absinthe=" <> inspect(Code.ensure_loaded?(Warden.Absinthe)))
      """)

    assert out =~ "status={403, true}"
    assert out =~ "absinthe=false"
  end

  test "absinthe without plug" do
    schema = """
    defmodule Standalone.Schema do
      use Absinthe.Schema
      use Warden.Absinthe, authorizer: Standalone.Authz

      query do
        field :secret, :string do
          authorize role(:admin)
          resolve fn _, _ -> {:ok, "SECRET"} end
        end
      end
    end
    """

    dir =
      project("absinthe_only", ~s([{:absinthe, "~> 1.12"}]), %{
        "lib/authz.ex" => @authorizer,
        "lib/schema.ex" => schema
      })

    build!(dir)

    out =
      run!(dir, """
      {:ok, r} = Absinthe.run("{ secret }", Standalone.Schema, context: %{current_user: %{id: "u2", roles: [:viewer]}})
      IO.puts("data=" <> inspect(r.data))
      IO.puts("plug=" <> inspect(Code.ensure_loaded?(Warden.Plug)))
      """)

    assert out =~ ~s(data=%{"secret" => nil})
    assert out =~ "plug=false"
  end
end
