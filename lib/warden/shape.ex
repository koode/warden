defmodule Warden.Shape do
  @moduledoc false
  # Describes a term by its shape only (type, struct name, size), for error messages.
  # Error messages end up in logs and crash reports, and the terms they are about are
  # guarded values, check and policy answers, contexts and handler results: printing
  # them would leak what Warden guards. `nil`, `true` and `false` are shown as they are,
  # and so is the tag of a tagged tuple; nothing else is.

  @spec describe(term) :: String.t()
  def describe(term) when term in [nil, true, false], do: inspect(term)
  def describe(term) when is_atom(term), do: "an atom"
  def describe(term) when is_binary(term), do: "a string of #{byte_size(term)} bytes"
  def describe(term) when is_integer(term), do: "an integer"
  def describe(term) when is_float(term), do: "a float"
  def describe(%module{}), do: "a %#{inspect(module)}{} struct"
  def describe(term) when is_map(term), do: "a map with #{map_size(term)} keys"
  def describe([]), do: "an empty list"
  def describe(term) when is_list(term), do: list(term, 0)

  def describe(term) when is_tuple(term) and tuple_size(term) > 0 and is_atom(elem(term, 0)),
    do: "a {#{inspect(elem(term, 0))}, ...} tuple of size #{tuple_size(term)}"

  def describe(term) when is_tuple(term), do: "a tuple of size #{tuple_size(term)}"
  def describe(term) when is_pid(term), do: "a pid"
  def describe(term) when is_reference(term), do: "a reference"
  def describe(term) when is_function(term), do: "a function"
  def describe(_term), do: "a term"

  # Describes a caught raise, exit or throw by its kind and exception module only: an
  # exception message (a KeyError, a MatchError) can print the data it failed on.
  @spec failure(atom, term) :: String.t()
  def failure(:error, %module{__exception__: true}), do: "raised #{inspect(module)}"
  def failure(:error, reason), do: "raised #{describe(reason)}"
  def failure(:exit, reason), do: "exited with #{describe(reason)}"
  def failure(:throw, value), do: "threw #{describe(value)}"

  defp list([], count), do: "a list of #{count} elements"
  defp list([_head | tail], count), do: list(tail, count + 1)
  defp list(_improper_tail, _count), do: "an improper list"
end
