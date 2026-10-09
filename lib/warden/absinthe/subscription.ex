defmodule Warden.Absinthe.Subscription do
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
  # Called by `Absinthe.Type.function/2` for `{:ref, Warden.Absinthe.Subscription, identifier}`.
  def __absinthe_function__({:config, field_ident, original, spec}, :config) do
    fn args, info -> config(field_ident, original, spec, args, info) end
  end

  defp config(field_ident, original, spec, args, info) do
    authorizer = spec.authorizer
    context = Map.get(info, :context, %{})
    actor = Actor.build(authorizer, context)

    with :ok <- subscribe_checks(spec.pre, actor, field_ident, args, context, authorizer),
         :ok <-
           return_checks(Map.get(spec, :return), actor, field_ident, args, context, authorizer),
         {:ok, config} <- user_config(field_ident, original, args, info) do
      {:ok, fingerprint(config, actor, context, authorizer)}
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

    case Warden.Absinthe.Middleware.run_checks(checks, base, authorizer) do
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

  defp return_checks(nil, _actor, _field, _args, _context, _authorizer), do: :ok

  defp return_checks(
         %{type: type, rule: rule, members: members},
         actor,
         field,
         args,
         context,
         authorizer
       ) do
    base = %Check{
      actor: actor,
      value: nil,
      args: args || %{},
      context: context,
      field: field,
      parent_type: :subscription
    }

    abstract_denial =
      if rule do
        case Warden.Rule.evaluate(rule, %{base | type: type}, authorizer) do
          :ok -> nil
          {:deny, failure} -> {type, rule, failure}
        end
      end

    member_denial =
      if members do
        results =
          Enum.map(members, fn {member, member_rule} ->
            case Warden.Rule.evaluate(member_rule, %{base | type: member}, authorizer) do
              :ok -> :ok
              {:deny, failure} -> {member, member_rule, failure}
            end
          end)

        if Enum.all?(results, &(&1 != :ok)), do: hd(results)
      end

    denial = abstract_denial || member_denial

    case denial do
      nil ->
        :ok

      {denied_type, denied_rule, failure} ->
        denial = %Denial{
          kind: :subscribe,
          rule: denied_rule,
          failed_rule: failure.failed_rule,
          missing_roles: failure.missing_roles,
          missing_permissions: failure.missing_permissions,
          actor: actor,
          path: [Atom.to_string(field)],
          field: field,
          parent_type: :subscription,
          type: denied_type
        }

        {:error, subscribe_error(authorizer, denial)}
    end
  end

  # A subscription cannot be "null": every denial refuses it. When the handler does not
  # return an error, the default error is used.
  defp subscribe_error(authorizer, denial) do
    term =
      case Warden.Absinthe.Middleware.call_deny(authorizer, denial) do
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

  # Absinthe reads the config with `config[:context_id]`, so it may be a keyword list or
  # a map. Sharing is off unless the authorizer opts in with `actor_key/2`; without a
  # `context_id`, Absinthe gives every subscription its own id.
  defp fingerprint(config, actor, context, authorizer)
       when is_list(config) or is_map(config) do
    case config[:context_id] do
      empty when empty in [nil, false] ->
        config

      context_id ->
        if authorizer.__warden_dedup__() do
          case authorizer.actor_key(actor, context) do
            nil ->
              drop_context_id(config)

            key when is_binary(key) ->
              put_context_id(config, "#{context_id}:warden:#{key}")

            other ->
              raise Warden.PolicyError,
                    "#{inspect(authorizer)}.actor_key/2 must return a string or nil, got: " <>
                      inspect(other)
          end
        else
          drop_context_id(config)
        end
    end
  end

  defp fingerprint(config, _actor, _context, _authorizer), do: config

  defp drop_context_id(config) when is_list(config), do: Keyword.delete(config, :context_id)
  defp drop_context_id(config) when is_map(config), do: Map.delete(config, :context_id)

  defp put_context_id(config, id) when is_list(config), do: Keyword.put(config, :context_id, id)
  defp put_context_id(config, id) when is_map(config), do: Map.put(config, :context_id, id)
end
