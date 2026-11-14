# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Info do
    @moduledoc false
    # Reads the compiled plan of a `Warden.Ecto.Policy` (`__warden_ecto__(:info)`).

    @spec ecto_policy?(term) :: boolean
    def ecto_policy?(policy) when is_atom(policy) do
      Code.ensure_loaded?(policy) and function_exported?(policy, :__warden_ecto__, 1)
    end

    def ecto_policy?(_policy), do: false

    @spec fetch!(term) :: map
    def fetch!(policy) do
      if ecto_policy?(policy),
        do: policy.__warden_ecto__(:info),
        else: raise(Warden.PolicyError, "#{inspect(policy)} is not a Warden.Ecto.Policy")
    end

    # The Ecto policy that the authorizer lists for `schema`.
    @spec policy_for!(module, module) :: map
    def policy_for!(authorizer, schema) do
      case Warden.Policy.policy_for(authorizer, schema) do
        nil ->
          raise Warden.PolicyError, """
          #{inspect(authorizer)} lists no policy for #{inspect(schema)} in its `policies:`\
          """

        policy ->
          fetch!(policy)
      end
    end

    @spec ensure_action!(map, atom) :: :ok
    def ensure_action!(info, action) do
      if Map.has_key?(info.actions, action) do
        :ok
      else
        raise Warden.PolicyError, """
        #{inspect(info.policy)} has no action #{inspect(action)} (actions: \
        #{inspect(Map.keys(info.actions))})\
        """
      end
    end

    # What a value is, for error messages: its shape, never its contents (a callback's
    # answer or a row may hold data that must not reach a log). One description for every
    # layer: `Warden.Shape`.
    @spec shape(term) :: String.t()
    def shape(value), do: Warden.Shape.describe(value)

    # The query prefix a loaded struct came from (`nil` for the default).
    @spec prefix(term) :: String.t() | nil
    def prefix(%{__meta__: %Ecto.Schema.Metadata{prefix: prefix}}), do: prefix
    def prefix(_value), do: nil

    @spec repo!(map) :: module
    def repo!(%{repo: nil, policy: policy}) do
      raise Warden.PolicyError, """
      #{inspect(policy)} needs a `:repo` option for the queries Warden runs itself\
      """
    end

    def repo!(%{repo: repo}), do: repo
  end
end
