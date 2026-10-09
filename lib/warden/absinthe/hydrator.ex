# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Hydrator do
    @moduledoc false
    # Absinthe's `{:meta, keyword}` hydration replaces a node's whole meta
    # (`Absinthe.Phase.Schema.Hydrate.apply_hydration/2`), so a later `{:meta, _}` would
    # silently drop a rule set with `Warden.Absinthe.Hydrate.meta/2`. `Warden.Absinthe.Phase.Attach` installs
    # this hydrator, which keeps Warden's keys across later `{:meta, _}` hydrations and
    # rejects a later hydration that sets a Warden key to a different value.
    @behaviour Absinthe.Schema.Hydrator

    alias Absinthe.Phase.Schema.Hydrate

    @warden_keys [:warden_rule, :warden_args, :warden_list_policy]

    @impl true
    def apply_hydration(%{__private__: private} = node, {:meta, keyword_list})
        when is_list(keyword_list) do
      existing = private |> Keyword.get(:meta, []) |> Keyword.take(@warden_keys)

      for {key, old} <- existing,
          Keyword.has_key?(keyword_list, key),
          (new = Keyword.fetch!(keyword_list, key)) != old do
        raise CompileError,
          description:
            "hydrate/2 sets #{inspect(key)} on #{describe(node)} twice with different values " <>
              "(#{inspect(old)} and #{inspect(new)}); combine them in one Warden.Absinthe.Hydrate.meta/2"
      end

      merged = Keyword.merge(existing, keyword_list)
      Hydrate.apply_hydration(node, {:meta, merged})
    end

    def apply_hydration(node, hydration) do
      Hydrate.apply_hydration(node, hydration)
    end

    defp describe(%{name: name}) when is_binary(name), do: name
    defp describe(%{identifier: ident}), do: inspect(ident)
    defp describe(_), do: "a schema node"
  end
end
