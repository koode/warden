defmodule Mix.Tasks.Warden.Matrix do
  @shortdoc "Prints the Warden policy matrix, or rewrites its snapshot"

  @moduledoc """
  Prints the policy matrix of every `Warden.Test.Matrix` test, or rewrites their
  snapshots:

      mix warden.matrix                  # print the tables, to paste into a review
      mix warden.matrix --update         # rewrite the snapshot files
      mix warden.matrix test/authz       # only the matrix tests under a path

  It runs `mix test --only warden_matrix` in the test environment with the environment
  variable `WARDEN_MATRIX` set to `print` or `update`, so it finds the matrix tests by
  their `:warden_matrix` tag. Other arguments are passed to `mix test`. Consistency
  failures still fail the run; only the snapshot comparison is skipped.

  `--only` includes the matrix tests even when another of their tags is excluded in
  `test_helper.exs`, so anything the helper prepares only for such a tag (a database,
  for example) must also be prepared when `:warden_matrix` is included.
  """

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    {command, command_args, env} = command(args)
    shell_output = IO.stream(:stdio, :line)

    {_output, status} =
      System.cmd(command, command_args, env: env, into: shell_output, stderr_to_stdout: true)

    if status != 0,
      do: Mix.raise("mix warden.matrix: the matrix tests failed (exit status #{status})")

    :ok
  end

  @doc false
  @spec command([String.t()]) :: {String.t(), [String.t()], [{String.t(), String.t()}]}
  def command(args) do
    {update?, rest} = Enum.split_with(args, &(&1 == "--update"))
    mode = if update? == [], do: "print", else: "update"
    env = [{"MIX_ENV", "test"}, {"WARDEN_MATRIX", mode}]
    {"mix", ["test", "--only", "warden_matrix" | rest], env}
  end
end
