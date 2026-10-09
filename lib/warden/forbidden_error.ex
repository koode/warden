defmodule Warden.ForbiddenError do
  @moduledoc """
  Raised by `Warden.authorize!/3` and `Warden.Plug.authorize!/3` when the actor is denied.

  It carries the `%Warden.Denial{}` and `plug_status: 403`, so Phoenix (through
  `Plug.Exception`) renders it as a 403 without Warden depending on Plug.

  The message is `"Forbidden"`. It names the missing roles and permissions only when
  the authorizer sets `expose_denial_reasons: true`.
  """

  # The denial holds the actor and its subject (the whole user record). Keep them out of
  # logs and crash reports; `error.denial` stays available to code.
  @derive {Inspect, only: [:message, :plug_status]}
  defexception message: "Forbidden", denial: nil, plug_status: 403

  @type t :: %__MODULE__{message: String.t(), denial: Warden.Denial.t() | nil, plug_status: 403}

  @doc false
  @spec for_denial(Warden.Denial.t(), map) :: t
  def for_denial(%Warden.Denial{} = denial, catalog) do
    message =
      if catalog[:expose_denial_reasons] do
        "Forbidden (missing roles: #{inspect(denial.missing_roles)}, " <>
          "missing permissions: #{inspect(denial.missing_permissions)})"
      else
        "Forbidden"
      end

    %__MODULE__{message: message, denial: denial}
  end
end
