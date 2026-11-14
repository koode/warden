# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Phase.Publish do
    @moduledoc false
    # Inserted before the resolution phase by `Warden.Absinthe.Subscription.run_docset/3`
    # only. It marks the execution as published by Warden's loop, which skips the push of
    # a denied subscription root; the root middleware warns when the mark is missing.

    use Absinthe.Phase

    alias Warden.Absinthe.Middleware

    @impl Absinthe.Phase
    def run(%{execution: execution} = blueprint, _opts) do
      acc = Middleware.mark_published(execution.acc)
      marked = %{blueprint | execution: %{execution | acc: acc}}
      {:ok, marked}
    end
  end
end
