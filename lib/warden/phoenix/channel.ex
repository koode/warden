# Compiled only when the optional `phoenix` dependency is present.
if Code.ensure_loaded?(Phoenix.Channel) do
  defmodule Warden.Phoenix.Channel do
    @moduledoc """
    Authorization for Phoenix channels: a rule checked at join and again while the
    channel lives. Needs the `phoenix` dependency.

    ## In a channel

        defmodule MyAppWeb.WorkspaceChannel do
          use Phoenix.Channel
          import Warden.Rule

          use Warden.Phoenix.Channel,
            rule: check(:workspace_member),
            value: &workspace_id/1,
            recheck: [:every_push, {:every, :timer.minutes(1)}]

          @impl true
          def join("workspace:" <> _id, _params, socket), do: {:ok, socket}

          defp workspace_id("workspace:" <> id), do: id
        end

    `use Warden.Phoenix.Channel` must come after `use Phoenix.Channel`. Options:

      * `:rule` (required) - the rule the socket's actor must pass to join and to stay
        joined.
      * `:value` - the guarded value given to the rule (`Warden.Check.value`), a function
        of the topic (`fn topic -> ... end`) or of the topic and the join params
        (`fn topic, params -> ... end`). Default: no value (`nil`). It runs on every
        check, so a rule always sees the value as it is now; keep it cheap.
      * `:recheck` - when to check the rule again after the join: `:every_push`,
        `{:every, milliseconds}`, a list of both, or `[]` for the join only. Default:
        `:every_push`.
      * `:authorizer` - the authorizer module. Resolution order: this option, then the
        configured default (`config :warden, authorizer: MyApp.Authz`).
      * `:on_deny` - `{module, function}` called as `function(socket, denial)` on a
        denial. It returns the map the client receives (see below); any other return
        is ignored and the default map is sent. It cannot let a denied socket through.
        Checked at compile time like the `Warden.Plug` option of the same name.

    The options are validated at compile time: an unknown option, a rule that names an
    unknown role, permission or check, a missing authorizer, a `value:` that is not a
    function of arity 1 or 2, or a bad `on_deny:` fails compilation (`ArgumentError`).

    ## What is checked when

      * **Join.** The rule is checked before your `join/3` runs. A denied join returns
        `{:error, reply}` to the client and your `join/3` is never called.
      * **`:every_push`.** The rule is checked before every callback that can send
        something to the client: `handle_out/3` for every broadcast, and your
        `handle_in/3`, `handle_info/2`, `handle_call/3` and `handle_cast/2` when you
        define them. A denied broadcast is dropped, and the callback does not run.
        Phoenix sends a broadcast past the channel process for every event the channel
        does not intercept, so with `:every_push` Warden intercepts every event. Your
        own `intercept/1` list and `handle_out/3` keep working: an allowed broadcast of
        an event you intercept goes to your `handle_out/3`, any other allowed broadcast
        is pushed unchanged. The cost is the one `intercept/1` documents: each
        broadcast is encoded once per subscriber instead of once in total.
      * **`{:every, ms}`.** A timer checks the rule every `ms` milliseconds, so a
        channel that receives nothing still ends when access ends. The timer message
        never reaches your `handle_info/2`.

    On a denial after the join, Warden pushes the event `"warden:denied"` with the reply
    map, then stops the channel with reason `{:shutdown, :forbidden}` (the client sees
    the channel close). Nothing else is pushed after that by Warden. Your `terminate/2`
    is not wrapped: Phoenix calls it after a denial with reason
    `{:shutdown, :forbidden}`, and it must not push.

    The reply map is `%{reason: "unauthorized"}` for an anonymous actor and
    `%{reason: "forbidden"}` otherwise, unless `on_deny:` returns another map. It
    never holds the subject or the guarded value.

    ## How your callbacks are wrapped

    Warden adds a `@before_compile` hook. It makes your `join/3` (and, with
    `:every_push`, your `handle_out/3`, `handle_in/3`, `handle_info/2`,
    `handle_call/3` and `handle_cast/2`) overridable with `defoverridable` and defines a
    function of the same name that checks the rule first and then calls yours with
    `super`. Your functions keep their names, clauses and return values; define them
    as usual, anywhere in the module.

    ## The actor

    There is no cache. Every check builds the actor from the socket as it is now:
    `c:Warden.Authorizer.socket_context/1` (default `socket.assigns`), then
    `subject/1`, `roles/2` and `permissions/2`. An assign that a callback changes is
    seen by the next check, and a revoked role or membership is seen by the next push.
    Keep those callbacks cheap.

    ## By hand

    In a channel without `use Warden.Phoenix.Channel`, or for extra rules:

        def join("workspace:" <> id, _params, socket) do
          Warden.Phoenix.Channel.authorize_join(socket, check(:workspace_member), value: id)
        end

        def handle_in("rename", params, socket) do
          case Warden.Phoenix.Channel.authorize(socket, role(:admin)) do
            {:ok, socket} -> {:reply, :ok, rename(socket, params)}
            {:error, _denial} -> {:reply, {:error, %{reason: "forbidden"}}, socket}
          end
        end

    These check once, when called; they start no rechecks.
    """

    alias Phoenix.Socket
    alias Warden.{Actor, Decision, Denial, Rule}
    alias Warden.Authorizer.Callbacks

    require Logger

    @option_keys [:rule, :value, :recheck, :authorizer, :on_deny]
    @default_recheck [:every_push]
    @denied_event "warden:denied"
    @stop_reason {:shutdown, :forbidden}
    @state_key :warden_channel
    @push_callbacks [handle_in: 3, handle_call: 3, handle_cast: 2]

    @typedoc "The map a denied client receives."
    @type reply :: map

    @typedoc "The compiled channel options."
    @type config :: %{
            rule: Rule.t(),
            authorizer: module,
            on_deny: nil | {module, atom},
            every_push: boolean,
            interval: nil | pos_integer
          }

    defmacro __using__(opts) do
      env = __CALLER__

      if not Keyword.keyword?(opts) do
        raise ArgumentError,
              "Warden.Phoenix.Channel options must be a keyword list, got: #{Macro.to_string(opts)}"
      end

      config = build_config!(opts, env)
      value_function = value_function!(Keyword.get(opts, :value))

      quote do
        Warden.Phoenix.Channel.__ensure_channel__!(__MODULE__)
        @before_compile Warden.Phoenix.Channel
        @warden_channel_config unquote(Macro.escape(config))
        def __warden_channel__, do: @warden_channel_config

        unquote(value_function)
      end
    end

    # Runs when the module body runs, after the `use Phoenix.Channel` above it. Warden's
    # `@before_compile` hook must run after the Phoenix one, which defines
    # `__intercepts__/0` for Warden to override.
    @spec __ensure_channel__!(module) :: :ok
    def __ensure_channel__!(module) do
      if not Module.has_attribute?(module, :phoenix_intercepts) do
        raise ArgumentError,
              "#{inspect(module)}: `use Phoenix.Channel` before `use Warden.Phoenix.Channel`"
      end

      :ok
    end

    defp build_config!(opts, env) do
      reject_unknown_options!(opts)
      rule = fetch_rule!(opts, env)
      authorizer = opts |> Keyword.get(:authorizer) |> eval(env) |> Warden.resolve_authorizer!()
      validate_rule!(rule, authorizer)

      {every_push, interval} =
        opts |> Keyword.get(:recheck, @default_recheck) |> eval(env) |> recheck!()

      on_deny = opts |> Keyword.get(:on_deny) |> eval(env) |> on_deny!()

      %{
        rule: rule,
        authorizer: authorizer,
        on_deny: on_deny,
        every_push: every_push,
        interval: interval
      }
    end

    defp eval(quoted, env) do
      {value, _binding} = Code.eval_quoted(quoted, [], env)
      value
    end

    defp reject_unknown_options!(opts) do
      case Keyword.keys(opts) -- @option_keys do
        [] ->
          :ok

        unknown ->
          raise ArgumentError, "unknown Warden.Phoenix.Channel options: #{inspect(unknown)}"
      end
    end

    defp fetch_rule!(opts, env) do
      case Keyword.fetch(opts, :rule) do
        {:ok, rule} -> eval(rule, env)
        :error -> raise ArgumentError, "Warden.Phoenix.Channel needs a `rule:` option"
      end
    end

    defp validate_rule!(rule, authorizer) do
      case Rule.validate(rule, authorizer.__warden_catalog__()) do
        :ok ->
          :ok

        {:error, errors} ->
          reasons = Enum.join(errors, "; ")

          raise ArgumentError,
                "invalid Warden.Phoenix.Channel rule for #{inspect(authorizer)}: #{reasons}"
      end
    end

    defp recheck!(recheck) do
      entries = List.wrap(recheck)
      Enum.each(entries, &recheck_entry!/1)
      intervals = for {:every, interval} <- entries, do: interval
      {:every_push in entries, single_interval!(intervals, recheck)}
    end

    defp single_interval!([], _recheck), do: nil
    defp single_interval!([interval], _recheck), do: interval

    defp single_interval!(_intervals, recheck) do
      raise ArgumentError,
            "Warden.Phoenix.Channel `recheck:` takes one {:every, ms}, got: #{inspect(recheck)}"
    end

    defp recheck_entry!(:every_push), do: :ok
    defp recheck_entry!({:every, interval}) when is_integer(interval) and interval > 0, do: :ok

    defp recheck_entry!(other) do
      raise ArgumentError, """
      Warden.Phoenix.Channel `recheck:` takes :every_push and {:every, ms} with a \
      positive integer ms, got: #{inspect(other)}\
      """
    end

    defp on_deny!(nil), do: nil

    defp on_deny!({module, function} = handler) when is_atom(module) and is_atom(function) do
      validate_on_deny!(module, function)
      handler
    end

    defp on_deny!(other) do
      raise ArgumentError,
            "Warden.Phoenix.Channel `on_deny:` must be {module, function}, got: #{inspect(other)}"
    end

    # A handler module that is being compiled right now (the channel itself, with
    # `on_deny: {__MODULE__, :deny}`) cannot be checked yet; its function may be defined
    # further down the file. Every other module must exist and export `function/2`.
    defp validate_on_deny!(module, function) do
      cond do
        Module.open?(module) ->
          :ok

        match?({:module, _module}, Code.ensure_compiled(module)) and
            function_exported?(module, function, 2) ->
          :ok

        true ->
          raise ArgumentError, """
          Warden.Phoenix.Channel `on_deny: {#{inspect(module)}, #{inspect(function)}}`: \
          #{inspect(module)}.#{function}/2 does not exist\
          """
      end
    end

    # The value function is written into the channel as code (not evaluated here), so it
    # may call the channel's own private functions. Its arity is read from the code.
    defp value_function!(nil) do
      quote do
        def __warden_value__(_topic, _params), do: nil
      end
    end

    defp value_function!(quoted) do
      case value_arity(quoted) do
        1 ->
          quote do
            def __warden_value__(topic, _params), do: unquote(quoted).(topic)
          end

        2 ->
          quote do
            def __warden_value__(topic, params), do: unquote(quoted).(topic, params)
          end

        _other ->
          raise ArgumentError, """
          Warden.Phoenix.Channel `value:` must be nil or a function of the topic \
          (arity 1) or of the topic and the join params (arity 2), got: \
          #{Macro.to_string(quoted)}\
          """
      end
    end

    defp value_arity({:fn, _meta, [{:->, _clause_meta, [arguments, _body]} | _clauses]}) do
      case arguments do
        [{:when, _when_meta, arguments_and_guard}] -> length(arguments_and_guard) - 1
        arguments -> length(arguments)
      end
    end

    defp value_arity({:&, _meta, [{:/, _slash_meta, [_function, arity]}]}) when is_integer(arity),
      do: arity

    defp value_arity({:&, _meta, [body]}) do
      {_body, arity} =
        Macro.prewalk(body, 0, fn
          {:&, _placeholder_meta, [position]} = placeholder, highest when is_integer(position) ->
            {placeholder, max(position, highest)}

          node, highest ->
            {node, highest}
        end)

      arity
    end

    defp value_arity(_quoted), do: nil

    defmacro __before_compile__(env) do
      config = Module.get_attribute(env.module, :warden_channel_config)
      defines? = &Module.defines?(env.module, &1)

      if not defines?.({:join, 3}) do
        raise ArgumentError,
              "#{inspect(env.module)} uses Warden.Phoenix.Channel but defines no join/3"
      end

      intercepts = Module.get_attribute(env.module, :phoenix_intercepts)
      push_guards = if config.every_push, do: push_guards(defines?, intercepts), else: []
      info_guard = info_guard(config, defines?)

      quote do
        unquote(join_guard())
        unquote_splicing(push_guards)
        unquote(info_guard)
      end
    end

    defp join_guard do
      quote do
        defoverridable join: 3

        @impl Phoenix.Channel
        def join(topic, params, socket) do
          case Warden.Phoenix.Channel.__authorize_join__(__MODULE__, topic, params, socket) do
            :ok ->
              joined = super(topic, params, socket)
              Warden.Phoenix.Channel.__joined__(__MODULE__, joined, params)

            {:error, _reply} = refused ->
              refused
          end
        end
      end
    end

    defp push_guards(defines?, intercepts) do
      callback_guards =
        for {name, arity} <- @push_callbacks, defines?.({name, arity}) do
          callback_guard(name, arity)
        end

      [
        intercepts_override(),
        out_guard(defines?.({:handle_out, 3}), intercepts) | callback_guards
      ]
    end

    defp intercepts_override do
      quote do
        defoverridable __intercepts__: 0
        def __intercepts__, do: Warden.Phoenix.Channel.__all_events__()
      end
    end

    defp out_guard(true = _user_defines_handle_out, intercepts) do
      quote do
        defoverridable handle_out: 3

        @impl Phoenix.Channel
        def handle_out(event, payload, socket) do
          with :ok <- Warden.Phoenix.Channel.__recheck__(__MODULE__, socket) do
            if :lists.member(event, unquote(intercepts)) do
              super(event, payload, socket)
            else
              Warden.Phoenix.Channel.__push__(event, payload, socket)
            end
          end
        end
      end
    end

    defp out_guard(false = _user_defines_handle_out, _intercepts) do
      quote do
        @impl Phoenix.Channel
        def handle_out(event, payload, socket) do
          with :ok <- Warden.Phoenix.Channel.__recheck__(__MODULE__, socket) do
            Warden.Phoenix.Channel.__push__(event, payload, socket)
          end
        end
      end
    end

    # The socket is the last argument of every guarded callback.
    defp callback_guard(name, arity) do
      socket = Macro.var(:socket, __MODULE__)
      arguments = Macro.generate_arguments(arity - 1, __MODULE__) ++ [socket]

      quote do
        defoverridable [{unquote(name), unquote(arity)}]

        @impl Phoenix.Channel
        def unquote(name)(unquote_splicing(arguments)) do
          with :ok <- Warden.Phoenix.Channel.__recheck__(__MODULE__, unquote(socket)) do
            super(unquote_splicing(arguments))
          end
        end
      end
    end

    defp info_guard(config, defines?) do
      user_defines_handle_info = defines?.({:handle_info, 2})
      timer = config.interval != nil

      cond do
        user_defines_handle_info and (timer or config.every_push) ->
          quote do
            defoverridable handle_info: 2
            unquote(timer_clause(timer))

            def handle_info(message, socket) do
              unquote(info_body(config.every_push))
            end
          end

        timer ->
          quote do
            unquote(timer_clause(true))

            def handle_info(message, socket) do
              Warden.Phoenix.Channel.__unexpected_message__(__MODULE__, message, socket)
            end
          end

        true ->
          nil
      end
    end

    defp timer_clause(false = _timer) do
      quote do
        @impl Phoenix.Channel
      end
    end

    defp timer_clause(true = _timer) do
      quote do
        @impl Phoenix.Channel
        def handle_info({Warden.Phoenix.Channel, :recheck, _timer_ref} = message, socket) do
          Warden.Phoenix.Channel.__timer_recheck__(__MODULE__, message, socket)
        end
      end
    end

    defp info_body(true = _every_push) do
      quote do
        with :ok <- Warden.Phoenix.Channel.__recheck__(__MODULE__, socket) do
          super(message, socket)
        end
      end
    end

    defp info_body(false = _every_push) do
      quote do
        super(message, socket)
      end
    end

    @doc """
    Authorizes the socket's actor (built now from the current socket) for `rule` in
    `join/3`. Returns `{:ok, socket}` or `{:error, reply}`, the shape `join/3` returns,
    with the default reply map (`%{reason: "unauthorized"}` for an anonymous actor,
    `%{reason: "forbidden"}` otherwise).

        def join("workspace:" <> id, _params, socket) do
          Warden.Phoenix.Channel.authorize_join(socket, check(:member), value: id)
        end

        Warden.Phoenix.Channel.authorize_join(socket, check(:member), value: id, authorizer: MyApp.Authz)

    Options: `:value`; `:authorizer` (explicit option, then the configured default). It
    checks once and starts no rechecks; use `use Warden.Phoenix.Channel` for those. An
    unknown role, permission or check raises `Warden.PolicyError`.
    """
    @spec authorize_join(Socket.t(), Rule.t(), keyword) :: {:ok, Socket.t()} | {:error, reply}
    def authorize_join(%Socket{} = socket, rule, opts \\ []) do
      case authorize(socket, rule, opts) do
        {:ok, socket} ->
          {:ok, socket}

        {:error, denial} ->
          reply = default_reply(denial)
          {:error, reply}
      end
    end

    @doc """
    Authorizes the socket's actor (built now from the current socket) for `rule`, for
    example in `handle_in/3`. Returns `{:ok, socket}` (the socket unchanged) or
    `{:error, %Warden.Denial{}}`, and sends nothing to the client.

        Warden.Phoenix.Channel.authorize(socket, check(:owner), value: message)
        Warden.Phoenix.Channel.authorize(socket, check(:owner), value: message, authorizer: MyApp.Authz)

    Options: `:value`; `:authorizer` (explicit option, then the configured default). An
    unknown role, permission or check raises `Warden.PolicyError`.
    """
    @spec authorize(Socket.t(), Rule.t(), keyword) :: {:ok, Socket.t()} | {:error, Denial.t()}
    def authorize(%Socket{} = socket, rule, opts \\ []) do
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))

      with :ok <- check(socket, rule, authorizer, Keyword.get(opts, :value)) do
        {:ok, socket}
      end
    end

    @doc """
    Builds the actor for the socket now, from the current socket context. Nothing is
    stored in the socket. Pass it to the core API to reuse it for several checks; the
    roles are then frozen for as long as you hold it.

        actor = Warden.Phoenix.Channel.actor(socket)                          # configured default
        actor = Warden.Phoenix.Channel.actor(socket, authorizer: MyApp.Authz) # explicit

    Option `:authorizer`: explicit option, else the configured default.
    """
    @spec actor(Socket.t(), keyword) :: Actor.t()
    def actor(%Socket{} = socket, opts \\ []) do
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
      context = Callbacks.socket_context(authorizer, socket)
      Warden.actor(context, authorizer: authorizer)
    end

    # No cache: the actor always reflects the socket as it is now.
    defp check(socket, rule, authorizer, value) do
      context = Callbacks.socket_context(authorizer, socket)
      decision_opts = [authorizer: authorizer, value: value]
      Decision.authorize(context, rule, decision_opts, :channel)
    end

    defp default_reply(%Denial{actor: actor}) do
      if Actor.anonymous?(actor) do
        %{reason: "unauthorized"}
      else
        %{reason: "forbidden"}
      end
    end

    defp reply(socket, denial, %{on_deny: {module, function}}) do
      case apply(module, function, [socket, denial]) do
        reply when is_map(reply) -> reply
        _ignored -> default_reply(denial)
      end
    end

    defp reply(_socket, denial, %{on_deny: nil}), do: default_reply(denial)

    defp guarded_check(module, socket, topic, params) do
      %{rule: rule, authorizer: authorizer} = module.__warden_channel__()
      value = module.__warden_value__(topic, params)
      check(socket, rule, authorizer, value)
    end

    defp state!(module, %Socket{private: private}) do
      case Map.fetch(private, @state_key) do
        {:ok, state} ->
          state

        :error ->
          raise Warden.PolicyError, """
          #{inspect(module)}: the socket has lost Warden's channel state; a callback \
          returned a socket that was not derived from the one it received\
          """
      end
    end

    defp put_state(socket, state) do
      private = Map.put(socket.private, @state_key, state)
      %{socket | private: private}
    end

    defp deny(module, socket, denial) do
      reply = reply(socket, denial, module.__warden_channel__())
      Phoenix.Channel.push(socket, @denied_event, reply)
      {:stop, @stop_reason, socket}
    end

    defp schedule(%{interval: nil}), do: nil

    defp schedule(%{interval: interval}) do
      timer_ref = make_ref()
      Process.send_after(self(), {__MODULE__, :recheck, timer_ref}, interval)
      timer_ref
    end

    @spec __all_events__() :: Warden.Phoenix.Channel.AllEvents.t()
    def __all_events__, do: %Warden.Phoenix.Channel.AllEvents{}
    @spec __authorize_join__(module, String.t(), map, Socket.t()) :: :ok | {:error, reply}
    def __authorize_join__(module, topic, params, socket) do
      case guarded_check(module, socket, topic, params) do
        :ok ->
          :ok

        {:error, denial} ->
          reply = reply(socket, denial, module.__warden_channel__())
          {:error, reply}
      end
    end

    @spec __joined__(module, term, map) :: term
    def __joined__(module, {:ok, %Socket{} = socket}, params),
      do: {:ok, start_guard(module, socket, params)}

    def __joined__(module, {:ok, reply, %Socket{} = socket}, params),
      do: {:ok, reply, start_guard(module, socket, params)}

    def __joined__(_module, other, _params), do: other

    defp start_guard(module, socket, params) do
      timer_ref = schedule(module.__warden_channel__())
      put_state(socket, %{params: params, timer_ref: timer_ref})
    end

    @spec __recheck__(module, Socket.t()) :: :ok | {:stop, term, Socket.t()}
    def __recheck__(module, socket) do
      %{params: params} = state!(module, socket)

      case guarded_check(module, socket, socket.topic, params) do
        :ok -> :ok
        {:error, denial} -> deny(module, socket, denial)
      end
    end

    # Only the timer Warden scheduled last counts. Any other recheck message (an old
    # timer, or one sent by other code) is dropped, so it cannot start a second timer.
    @spec __timer_recheck__(module, term, Socket.t()) ::
            {:noreply, Socket.t()} | {:stop, term, Socket.t()}
    def __timer_recheck__(module, {__MODULE__, :recheck, timer_ref}, socket) do
      case state!(module, socket) do
        %{timer_ref: ^timer_ref} = state -> timer_recheck(module, socket, state)
        _other_timer -> {:noreply, socket}
      end
    end

    defp timer_recheck(module, socket, state) do
      with :ok <- __recheck__(module, socket) do
        timer_ref = schedule(module.__warden_channel__())
        socket = put_state(socket, %{state | timer_ref: timer_ref})
        {:noreply, socket}
      end
    end

    @spec __push__(String.t(), term, Socket.t()) :: {:noreply, Socket.t()}
    def __push__(event, payload, socket) do
      Phoenix.Channel.push(socket, event, payload)
      {:noreply, socket}
    end

    # Phoenix logs and ignores a message for a channel without handle_info/2. Warden
    # defines handle_info/2 for its timer, so it does the same for every other message.
    @spec __unexpected_message__(module, term, Socket.t()) :: {:noreply, Socket.t()}
    def __unexpected_message__(module, message, socket) do
      Logger.warning(fn ->
        "#{inspect(module)} received an unexpected message in handle_info/2: #{inspect(message)}"
      end)

      {:noreply, socket}
    end
  end
end
