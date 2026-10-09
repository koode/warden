# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Subscription do
    @moduledoc false
    # Wraps every subscription field's `config` function.
    #
    #   * Subscribe time: the root type rule, the field rule and the argument rules run
    #     before the user's `config`. A denial refuses the subscription.
    #   * `context_id`: Absinthe shares one resolution between subscriptions with the same
    #     `context_id` and document. Warden appends the actor key, so subscribers with
    #     different access never share a payload.

    alias Absinthe.Type
    alias Warden.Absinthe.Middleware
    alias Warden.{Actor, Authorizer, Check, Denial, Rule}

    def config_ref(field_ident, original, spec) do
      {:ref, __MODULE__, {:config, field_ident, original, spec}}
    end

    # Called by `Absinthe.Type.function/2` for `{:ref, Warden.Absinthe.Subscription, identifier}`.
    def __absinthe_function__({:config, field_ident, original, spec}, :config) do
      fn args, info -> config(field_ident, original, spec, args, info) end
    end

    defp config(field_ident, original, spec, args, info) do
      authorizer = spec.authorizer
      context = Map.get(info, :context, %{})
      actor = Actor.build(authorizer, context)

      base = %Check{
        actor: actor,
        value: nil,
        args: args || %{},
        context: context,
        field: field_ident,
        parent_type: :subscription
      }

      with :ok <- subscribe_checks(spec.pre, base, authorizer),
           :ok <- return_checks(Map.get(spec, :return), base, authorizer),
           {:ok, config} <- user_config(field_ident, original, args, info) do
        {:ok, fingerprint(config, actor, context, authorizer)}
      end
    end

    defp subscribe_checks(nil, _base, _authorizer), do: :ok

    defp subscribe_checks(%{checks: checks}, base, authorizer) do
      case Middleware.run_checks(checks, base, authorizer) do
        :ok ->
          :ok

        {:deny, _kind, rule, failure, extra} ->
          refuse(base, authorizer, rule, failure,
            type: Keyword.get(extra, :type),
            argument: Keyword.get(extra, :argument)
          )
      end
    end

    defp return_checks(nil, _base, _authorizer), do: :ok

    defp return_checks(%{type: type, rule: rule, members: members}, base, authorizer) do
      case abstract_denial(rule, type, base, authorizer) ||
             member_denial(members, base, authorizer) do
        nil ->
          :ok

        {denied_type, denied_rule, failure} ->
          refuse(base, authorizer, denied_rule, failure, type: denied_type)
      end
    end

    defp abstract_denial(nil, _type, _base, _authorizer), do: nil

    defp abstract_denial(rule, type, base, authorizer),
      do: return_denial(rule, type, base, authorizer)

    # Refused only when every possible concrete type denies.
    defp member_denial(nil, _base, _authorizer), do: nil

    defp member_denial(members, base, authorizer) do
      denials =
        Enum.map(members, fn {member, rule} -> return_denial(rule, member, base, authorizer) end)

      if Enum.all?(denials, &(&1 != nil)), do: hd(denials), else: nil
    end

    defp return_denial(rule, type, base, authorizer) do
      case Rule.evaluate(rule, %{base | type: type}, authorizer) do
        :ok -> nil
        {:deny, failure} -> {type, rule, failure}
      end
    end

    defp refuse(%Check{} = base, authorizer, rule, failure, extra) do
      denial = %Denial{
        kind: :subscribe,
        rule: rule,
        failed_rule: failure.failed_rule,
        missing_roles: failure.missing_roles,
        missing_permissions: failure.missing_permissions,
        actor: base.actor,
        path: [Atom.to_string(base.field)],
        field: base.field,
        parent_type: :subscription,
        type: Keyword.get(extra, :type),
        argument: Keyword.get(extra, :argument)
      }

      {:error, subscribe_error(authorizer, denial)}
    end

    # A subscription cannot be "null": every denial refuses it. When the handler does not
    # return an error, the default error is used.
    defp subscribe_error(authorizer, denial) do
      authorizer
      |> Middleware.call_deny(denial)
      |> refusal_term(authorizer, denial)
      |> to_error_map()
    end

    defp refusal_term({:error, term}, _authorizer, _denial), do: term

    defp refusal_term(_other, authorizer, denial) do
      {:error, term} = Authorizer.default_deny(denial, authorizer.__warden_catalog__())
      term
    end

    defp to_error_map([{_, _} | _] = kw), do: Map.new(kw)
    defp to_error_map(other), do: other

    defp user_config(field_ident, original, args, info) do
      case Type.function(%{config: original}, :config) do
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
        empty when empty in [nil, false] -> config
        context_id -> shared_context_id(config, context_id, actor, context, authorizer)
      end
    end

    defp fingerprint(config, _actor, _context, _authorizer), do: config

    defp shared_context_id(config, context_id, actor, context, authorizer) do
      if authorizer.__warden_dedup__() do
        put_actor_key(config, context_id, authorizer.actor_key(actor, context), authorizer)
      else
        drop_context_id(config)
      end
    end

    defp put_actor_key(config, _context_id, nil, _authorizer), do: drop_context_id(config)

    defp put_actor_key(config, context_id, key, _authorizer) when is_binary(key),
      do: put_context_id(config, "#{context_id}:warden:#{key}")

    defp put_actor_key(_config, _context_id, other, authorizer) do
      raise Warden.PolicyError,
            "#{inspect(authorizer)}.actor_key/2 must return a string or nil, got: " <>
              inspect(other)
    end

    defp drop_context_id(config) when is_list(config), do: Keyword.delete(config, :context_id)
    defp drop_context_id(config) when is_map(config), do: Map.delete(config, :context_id)

    defp put_context_id(config, id) when is_list(config), do: Keyword.put(config, :context_id, id)
    defp put_context_id(config, id) when is_map(config), do: Map.put(config, :context_id, id)
  end
end
