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
  IO.puts("phoenix=" <> inspect(Code.ensure_loaded?(Warden.Phoenix.Channel)))
  IO.puts("ecto=" <> inspect(Code.ensure_loaded?(Warden.Ecto)))
  IO.puts("ecto_policy=" <> inspect(Code.ensure_loaded?(Warden.Ecto.Policy)))
  IO.puts("test_helpers=" <> inspect(Code.ensure_loaded?(Warden.Test)))
  IO.puts("matrix=" <> inspect(Code.ensure_loaded?(Warden.Test.Matrix)))
  IO.puts("matrix_task=" <> inspect(Code.ensure_loaded?(Mix.Tasks.Warden.Matrix)))
  started = Enum.map(Application.started_applications(), &elem(&1, 0))
  IO.puts("ex_unit=" <> inspect(:code.is_loaded(ExUnit.AssertionError) != false or :ex_unit in started))
  """

  test "neither absinthe nor plug: explicit authorizer" do
    dir = project("core_explicit", "[]", %{"lib/authz.ex" => @authorizer})
    build!(dir)
    out = run!(dir, String.replace(@check_core, "AUTHZ", "authorizer: Standalone.Authz"))

    assert out =~ "authorize=:ok"
    assert out =~ "filter=[1, 2]"
    assert out =~ "absinthe=false"
    assert out =~ "plug=false"
    assert out =~ "phoenix=false"
    assert out =~ "ecto=false"
    assert out =~ "ecto_policy=false"
    assert out =~ "test_helpers=true"
    assert out =~ "matrix=false"
    assert out =~ "matrix_task=true"
    assert out =~ "ex_unit=false"
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

  test "field policies without any optional dependency" do
    fields = """
    defmodule Standalone.FieldsAuthz do
      use Warden.Authorizer, roles: [:admin], fields: [Standalone.NoteFields]

      @impl true
      def subject(context), do: context[:current_user]

      @impl true
      def roles(user, _context), do: user.roles
    end

    defmodule Standalone.Note do
      defstruct [:id, body: "secret"]
    end

    defmodule Standalone.NoteFields do
      use Warden.Fields, authorizer: Standalone.FieldsAuthz, for: Standalone.Note
      redact :body, with: "", unless: role(:admin)
    end
    """

    dir = project("fields_only", "[]", %{"lib/fields.ex" => fields})
    build!(dir)

    out =
      run!(dir, """
      viewer = %{current_user: %{id: "u2", roles: []}}
      notes = [%Standalone.Note{id: 1}, %Standalone.Note{id: 2}]
      redacted = Warden.redact(viewer, %{notes: notes}, deep: true, authorizer: Standalone.FieldsAuthz)
      IO.puts("bodies=" <> inspect(Enum.map(redacted.notes, & &1.body)))
      """)

    assert out =~ ~s(bodies=["", ""])
  end

  test "ecto without ecto_sql, absinthe or plug" do
    files = %{
      "lib/authz.ex" => """
      defmodule Standalone.Authz do
        use Warden.Authorizer,
          roles: [:admin],
          tenant_roles: [:member],
          policies: [Standalone.Docs]

        @impl true
        def subject(context), do: context[:current_user]

        @impl true
        def roles(_user, _context), do: []

        @impl true
        def tenant_roles(user, tenant, _context), do: Map.get(user.memberships, tenant, [])

        @impl true
        def tenants(actor, _context), do: Map.keys(actor.subject.memberships)
      end
      """,
      "lib/docs.ex" => """
      defmodule Standalone.Doc do
        use Ecto.Schema

        schema "docs" do
          field :workspace_id, :string
          field :public, :boolean
        end
      end

      defmodule Standalone.Docs do
        use Warden.Ecto.Policy,
          authorizer: Standalone.Authz,
          schema: Standalone.Doc,
          as: :doc,
          tenant: :workspace_id,
          actions: [:read]

        allow :read, rule: tenant_role(:member), where: [public: true]
      end
      """
    }

    dir = project("ecto_only", ~s([{:ecto, "~> 3.12"}]), files)
    build!(dir)

    out =
      run!(dir, """
      context = %{current_user: %{id: "u1", memberships: %{"w1" => [:member]}}}
      query = Warden.Ecto.scope(Standalone.Doc, context, :read, authorizer: Standalone.Authz)
      IO.puts("scope=" <> inspect(query))
      IO.puts("to_sql=" <> inspect(function_exported?(Warden.Ecto, :to_sql, 4)))
      IO.puts("matrix=" <> inspect(Code.ensure_loaded?(Warden.Test.Matrix)))
      IO.puts("absinthe_matrix=" <> inspect(Code.ensure_loaded?(Warden.Test.Absinthe)))
      IO.puts("absinthe=" <> inspect(Code.ensure_loaded?(Warden.Absinthe)))
      IO.puts("plug=" <> inspect(Code.ensure_loaded?(Warden.Plug)))
      """)

    assert out =~ ~s(where: d0.workspace_id == ^"w1" and d0.public == ^true)
    assert out =~ "to_sql=false"
    assert out =~ "matrix=true"
    assert out =~ "absinthe_matrix=false"
    assert out =~ "absinthe=false"
    assert out =~ "plug=false"
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
      IO.puts("phoenix=" <> inspect(Code.ensure_loaded?(Warden.Phoenix.Channel)))
      """)

    assert out =~ "status={403, true}"
    assert out =~ "absinthe=false"
    assert out =~ "phoenix=false"
  end

  test "phoenix without absinthe" do
    channel = """
    defmodule Standalone.RoomChannel do
      use Phoenix.Channel
      import Warden.Rule

      use Warden.Phoenix.Channel,
        rule: role(:admin),
        value: fn "room:" <> id -> id end,
        recheck: [:every_push, {:every, 60_000}]

      intercept(["edited"])

      @impl true
      def join("room:" <> _id, _params, socket), do: {:ok, socket}

      @impl true
      def handle_in("ping", _payload, socket), do: {:reply, :ok, socket}

      @impl true
      def handle_out("edited", payload, socket) do
        push(socket, "edited", payload)
        {:noreply, socket}
      end

      @impl true
      def handle_info(:tick, socket), do: {:noreply, socket}
    end
    """

    dir =
      project("phoenix_only", ~s([{:phoenix, "~> 1.7"}]), %{
        "lib/authz.ex" => @authorizer,
        "lib/room_channel.ex" => channel,
        "config/config.exs" => "import Config\nconfig :warden, authorizer: Standalone.Authz\n"
      })

    build!(dir)

    out =
      run!(dir, """
      import Warden.Rule
      socket = %Phoenix.Socket{assigns: %{current_user: %{id: "u2", roles: [:viewer]}}}
      {:error, %Warden.Denial{}} = Warden.Phoenix.Channel.authorize(socket, role(:admin))
      IO.puts("join=" <> inspect(Warden.Phoenix.Channel.authorize_join(socket, role(:admin))))
      IO.puts("intercepts=" <> inspect("any" in Standalone.RoomChannel.__intercepts__()))
      IO.puts("absinthe=" <> inspect(Code.ensure_loaded?(Warden.Absinthe)))
      """)

    assert out =~ ~s(join={:error, %{reason: "forbidden"}})
    assert out =~ "intercepts=true"
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
      IO.puts("absinthe_matrix=" <> inspect(Code.ensure_loaded?(Warden.Test.Absinthe)))
      IO.puts("matrix=" <> inspect(Code.ensure_loaded?(Warden.Test.Matrix)))
      IO.puts("plug=" <> inspect(Code.ensure_loaded?(Warden.Plug)))
      IO.puts("phoenix=" <> inspect(Code.ensure_loaded?(Warden.Phoenix.Channel)))
      """)

    assert out =~ ~s(data=%{"secret" => nil})
    assert out =~ "absinthe_matrix=true"
    assert out =~ "matrix=false"
    assert out =~ "plug=false"
    assert out =~ "phoenix=false"
  end
end
