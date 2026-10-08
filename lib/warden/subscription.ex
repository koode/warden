defmodule Warden.Subscription do
  @moduledoc false
  # Wraps every subscription field's `config` function.
  #
  #   * Subscribe time: the root type rule, the field rule and the argument rules run
  #     before the user's `config`. A denial refuses the subscription.
  #   * `context_id`: Absinthe shares one resolution between subscriptions with the same
  #     `context_id` and document. Warden appends the actor key, so subscribers with
  #     different access never share a payload.

  alias Warden.{Actor, Check, Denial}

  @doc false
  def config_ref(field_ident, original, spec) do
    {:ref, __MODULE__, {:config, field_ident, original, spec}}
  end

  @doc false
  # Called by `Absinthe.Type.function/2` for `{:ref, Warden.Subscription, identifier}`.
  def __absinthe_function__({:config, field_ident, original, spec}, :config) do
    fn args, info -> config(field_ident, original, spec, args, info) end
  end

  defp config(field_ident, original, spec, args, info) do
    authorizer = spec.authorizer
    context = Map.get(info, :context, %{})
    actor = Actor.build(authorizer, context)

    with :ok <- subscribe_checks(spec.pre, actor, field_ident, args, context, authorizer),
         {:ok, config} <- user_config(field_ident, original, args, info) do
      {:ok, fingerprint(config, actor, authorizer)}
    end
  end

  defp subscribe_checks(nil, _actor, _field, _args, _context, _authorizer), do: :ok

  defp subscribe_checks(%{checks: checks}, actor, field, args, context, authorizer) do
    base = %Check{
      actor: actor,
      value: nil,
      args: args || %{},
      context: context,
      field: field,
      parent_type: :subscription
    }

    case Warden.Middleware.run_checks(checks, base, authorizer) do
      :ok ->
        :ok

      {:deny, _kind, rule, failure, extra} ->
        denial = %Denial{
          kind: :subscribe,
          rule: rule,
          failed_rule: failure.failed_rule,
          missing_roles: failure.missing_roles,
          missing_permissions: failure.missing_permissions,
          actor: actor,
          path: [Atom.to_string(field)],
          field: field,
          parent_type: :subscription,
          type: Keyword.get(extra, :type),
          argument: Keyword.get(extra, :argument)
        }

        {:error, subscribe_error(authorizer, denial)}
    end
  end

  # A subscription cannot be "null": every denial refuses it. When the handler does not
  # return an error, the default error is used.
  defp subscribe_error(authorizer, denial) do
    term =
      case Warden.Middleware.call_deny(authorizer, denial) do
        {:error, term} ->
          term

        _ ->
          {:error, term} = Warden.Authorizer.default_deny(denial, authorizer.__warden_catalog__())
          term
      end

    case term do
      [{_, _} | _] = kw -> Map.new(kw)
      other -> other
    end
  end

  defp user_config(field_ident, original, args, info) do
    case Absinthe.Type.function(%{config: original}, :config) do
      nil ->
        {:ok, topic: Atom.to_string(field_ident)}

      fun when is_function(fun, 2) ->
        fun.(args, info)

      fun when is_function(fun, 1) ->
        fun.(args)
    end
  end

  defp fingerprint(config, actor, authorizer) when is_list(config) do
    case Keyword.fetch(config, :context_id) do
      {:ok, context_id} when not is_nil(context_id) ->
        key = authorizer.actor_key(actor)

        unless is_binary(key) do
          raise Warden.PolicyError,
                "#{inspect(authorizer)}.actor_key/1 must return a string, got: #{inspect(key)}"
        end

        Keyword.put(config, :context_id, "#{context_id}:warden:#{key}")

      _ ->
        config
    end
  end

  defp fingerprint(config, _actor, _authorizer), do: config
end
