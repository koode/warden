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
    # Before resolution it builds the actor of the document execution from its context,
    # once, and stores it in `acc` where every field rule and `Warden.Absinthe.actor/1`
    # read it. Absinthe calls this before every resolution pass; a later pass finds the
    # actor already there. A schema cannot add a phase to the document pipeline, which
    # the caller builds, and this callback is Absinthe's hook for setting `acc` before
    # resolution starts. A subscription publish is a new execution with an empty `acc`,
    # so it builds a new actor from the subscriber's context.
    #
    # `Absinthe.Pipeline.BatchResolver` (Absinthe.Plug's batch mode) calls it with an
    # execution that has no schema yet, so the authorizer is unknown: there the first
    # field rule builds the actor (`Warden.Absinthe.Middleware.actor/2`), shared by the
    # documents of the batch as before.
    #
    # `use Warden.Absinthe` adds this plugin to the schema's `plugins/0`.

    @behaviour Absinthe.Plugin

    alias Warden.Absinthe.Middleware

    def add_to(plugins), do: List.delete(plugins, __MODULE__) ++ [__MODULE__]

    @impl true
    def before_resolution(%{schema: schema, acc: acc, context: context} = exec)
        when is_atom(schema) and schema != nil do
      if function_exported?(schema, :__warden__, 1) do
        authorizer = schema.__warden__(:options).authorizer
        %{exec | acc: Middleware.with_actor(acc, context, authorizer)}
      else
        exec
      end
    end

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
