# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Plugin do
    @moduledoc false
    # Absinthe nulls every result node that carries an error, and a field's errors null
    # the whole field. So an error for a single denied list item cannot be returned from
    # the field's middleware without nulling the list. The post middleware records those
    # item errors in `resolution.acc`; this plugin then inserts `Warden.Absinthe.Phase.ItemErrors`
    # after the resolution phase, which attaches each error to the (already null) item.
    #
    # `use Warden.Absinthe` adds this plugin to the schema's `plugins/0`.

    @behaviour Absinthe.Plugin

    @doc false
    def add_to(plugins), do: List.delete(plugins, __MODULE__) ++ [__MODULE__]

    @impl true
    def before_resolution(exec), do: exec

    @impl true
    def after_resolution(exec), do: exec

    # Warden is the last plugin (`add_to/1` appends it). An empty `pipeline` means no other
    # plugin wants another resolution pass, so this is the final pass: run the phase
    # once. The phase drains the entries, so this never asks for a phase twice and cannot
    # make `Absinthe.Pipeline.BatchResolver` (which loops while plugins return phases)
    # spin.
    @impl true
    def pipeline([], exec) do
      if pending?(exec.acc), do: [Warden.Absinthe.Phase.ItemErrors], else: []
    end

    def pipeline(pipeline, _exec), do: pipeline

    defp pending?(%{Warden => %{pending: true}}), do: true
    defp pending?(_), do: false
  end
end
