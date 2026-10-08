defmodule Warden.Plugin do
  @moduledoc false
  # Absinthe nulls every result node that carries an error, and a field's errors null
  # the whole field. So an error for a single denied list item cannot be returned from
  # the field's middleware without nulling the list. The post middleware records those
  # item errors in `resolution.acc`; this plugin then inserts `Warden.Phase.ItemErrors`
  # after the resolution phase, which attaches each error to the (already null) item.
  #
  # `use Warden.Schema` adds this plugin to the schema's `plugins/0`.

  @behaviour Absinthe.Plugin

  @doc false
  def add_to(plugins) do
    if __MODULE__ in plugins, do: plugins, else: plugins ++ [__MODULE__]
  end

  @impl true
  def before_resolution(exec), do: exec

  @impl true
  def after_resolution(exec), do: exec

  @impl true
  def pipeline(pipeline, exec) do
    case exec.acc do
      %{Warden => %{item_errors: [_ | _]}} -> pipeline ++ [Warden.Phase.ItemErrors]
      _ -> pipeline
    end
  end
end
