defmodule Warden.Test.Helpers do
  @moduledoc false

  alias Warden.Test.Data

  @doc "Runs a document against `schema` as `user` (a map or nil)."
  def run(doc, user, opts \\ []) do
    schema = Keyword.get(opts, :schema, Warden.Test.Schema)
    extra = Keyword.get(opts, :context, %{})
    variables = Keyword.get(opts, :variables, %{})
    context = Map.merge(%{current_user: user, test_pid: self()}, extra)

    case Absinthe.run(doc, schema, context: context, variables: variables) do
      {:ok, result} -> result
      other -> raise "unexpected result: #{inspect(other)}"
    end
  end

  def admin, do: Data.as(:admin, "u1")
  def editor, do: Data.as(:editor, "u3")
  def viewer, do: Data.as(:viewer, "u2")
  def nobody, do: Data.as([], "u4")
  def auditor, do: Data.as(:auditor, "u5")

  def error_paths(%{errors: errors}), do: errors |> Enum.map(& &1.path) |> Enum.sort()
  def error_paths(_), do: []

  def forbidden?(error), do: error.message == "Forbidden" and error[:extensions][:code] == "FORBIDDEN"

  @doc "Collects every {:resolved, tag} message already in the mailbox."
  def resolved do
    receive do
      {:resolved, tag} -> [tag | resolved()]
    after
      0 -> []
    end
  end

  @doc "Deep-searches a response for a string value."
  def contains?(data, needle) when is_binary(data), do: data == needle
  def contains?(data, needle) when is_map(data), do: Enum.any?(data, fn {_, v} -> contains?(v, needle) end)
  def contains?(data, needle) when is_list(data), do: Enum.any?(data, &contains?(&1, needle))
  def contains?(_, _), do: false
end
