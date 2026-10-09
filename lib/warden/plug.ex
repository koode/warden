# Compiled only when the optional `plug` dependency is present.
if Code.ensure_loaded?(Plug) do
  defmodule Warden.Plug do
    @moduledoc """
    Authorization for Plug and Phoenix. Needs the `plug` dependency.

    ## As a plug

        import Warden.Rule

        plug Warden.Plug, rule: role(:admin), authorizer: MyApp.Authz   # explicit
        plug Warden.Plug, rule: role(:admin)                            # configured default

    Options:

      * `:rule` (required) - the rule every request must pass.
      * `:authorizer` - the authorizer module. Resolution order: this option, then the
        configured default (`config :warden, authorizer: MyApp.Authz`).
      * `:on_deny` - `{module, function}` called as `function(conn, denial)` on denial.
        Overrides the authorizer's `c:Warden.Authorizer.deny_conn/2`. `init/1` checks that
        `module.function/2` exists (except for a module that is still being compiled,
        such as the controller itself).

    `init/1` resolves the authorizer and validates the rule against its catalog. Phoenix
    runs `init/1` at compile time, so an unknown role, permission or check, or a missing
    authorizer, fails compilation (`ArgumentError`).

    On denial the handler runs: `on_deny`, else the authorizer's `deny_conn/2`, else the
    default, which sends `401 Unauthorized` to an anonymous actor and `403 Forbidden`
    otherwise. Whatever the handler returns, the conn is halted, and when the handler sent
    no response the default response is sent. A handler cannot let a denied request
    through.

    ## In a controller

        # configured default
        with {:ok, conn} <- Warden.Plug.authorize(conn, check(:owner), value: post) do
          render(conn, :show, post: post)
        end

        # explicit authorizer
        with {:ok, conn} <-
               Warden.Plug.authorize(conn, check(:owner), value: post, authorizer: MyApp.Authz) do
          render(conn, :show, post: post)
        end

        conn = Warden.Plug.authorize!(conn, check(:owner), value: post)                         # default
        conn = Warden.Plug.authorize!(conn, check(:owner), value: post, authorizer: MyApp.Authz) # explicit

    `authorize/3` returns `{:ok, conn}` or `{:error, %Warden.Denial{}}` and sends nothing;
    `authorize!/3` returns the conn or raises `Warden.ForbiddenError` (rendered as 403).
    Options: `:value`, and `:authorizer` (explicit option, then the configured default).

    ## The actor

    There is no cache. Every check (`call/2`, `authorize/3`, `authorize!/3`) builds the
    actor from the current conn: `c:Warden.Authorizer.conn_context/1` (default
    `Map.put(conn.assigns, :conn, conn)`), then `subject/1`, `roles/2` and
    `permissions/2`. A later plug that logs out, impersonates, drops privileges or
    switches the tenant is always seen. Keep those callbacks cheap: read from the assigns
    or the context, and load data in an earlier plug.

    To reuse one actor across several checks, build it once with `actor/2` (or
    `Warden.actor/2`) and pass it to the core API. That is a deliberate choice: the roles
    are frozen for as long as you hold that actor.
    """

    @behaviour Plug

    import Plug.Conn

    alias Warden.{Actor, Denial, Rule}

    @option_keys [:rule, :authorizer, :on_deny]

    @typedoc "The compiled plug options."
    @type config :: %{rule: Rule.t(), authorizer: module, on_deny: nil | {module, atom}}

    @impl Plug
    @spec init(keyword) :: config
    def init(opts) when is_list(opts) do
      reject_unknown_options!(opts)
      rule = fetch_rule!(opts)
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
      validate_rule!(rule, authorizer)
      on_deny = fetch_on_deny!(opts)

      %{rule: rule, authorizer: authorizer, on_deny: on_deny}
    end

    defp reject_unknown_options!(opts) do
      case Keyword.keys(opts) -- @option_keys do
        [] -> :ok
        unknown -> raise ArgumentError, "unknown Warden.Plug options: #{inspect(unknown)}"
      end
    end

    defp fetch_rule!(opts) do
      case Keyword.fetch(opts, :rule) do
        {:ok, rule} -> rule
        :error -> raise ArgumentError, "Warden.Plug needs a `rule:` option"
      end
    end

    defp validate_rule!(rule, authorizer) do
      case Rule.validate(rule, authorizer.__warden_catalog__()) do
        :ok ->
          :ok

        {:error, errors} ->
          raise ArgumentError,
                "invalid Warden.Plug rule for #{inspect(authorizer)}: " <> Enum.join(errors, "; ")
      end
    end

    defp fetch_on_deny!(opts) do
      case Keyword.get(opts, :on_deny) do
        nil ->
          nil

        {mod, fun} = handler when is_atom(mod) and is_atom(fun) ->
          validate_on_deny!(mod, fun)
          handler

        other ->
          raise ArgumentError,
                "Warden.Plug `on_deny:` must be {module, function}, got: #{inspect(other)}"
      end
    end

    # A handler module that is being compiled right now (a controller that passes
    # `on_deny: {__MODULE__, :deny}`) cannot be checked yet; its function may be defined
    # further down the file. Every other module must exist and export `fun/2`.
    defp validate_on_deny!(mod, fun) do
      cond do
        Module.open?(mod) ->
          :ok

        match?({:module, _}, Code.ensure_compiled(mod)) and function_exported?(mod, fun, 2) ->
          :ok

        true ->
          raise ArgumentError,
                "Warden.Plug `on_deny: {#{inspect(mod)}, #{inspect(fun)}}`: " <>
                  "#{inspect(mod)}.#{fun}/2 does not exist"
      end
    end

    @impl Plug
    @spec call(Plug.Conn.t(), config) :: Plug.Conn.t()
    def call(conn, %{rule: rule, authorizer: authorizer} = config) do
      {actor, context} = build_actor(conn, authorizer)

      case Warden.authorize(actor, rule, authorizer: authorizer, context: context) do
        :ok -> conn
        {:error, denial} -> deny(conn, denial, config)
      end
    end

    @doc """
    Builds the actor for the conn now, from the current conn context. Nothing is stored
    in the conn. Pass it to the core API to reuse it for several checks; the roles are
    then frozen for as long as you hold it.

        actor = Warden.Plug.actor(conn)                          # configured default
        actor = Warden.Plug.actor(conn, authorizer: MyApp.Authz) # explicit
        Warden.filter(actor, check(:owner), posts)

    Option `:authorizer`: explicit option, else the configured default.
    """
    @spec actor(Plug.Conn.t(), keyword) :: Actor.t()
    def actor(%Plug.Conn{} = conn, opts \\ []) do
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
      {actor, _context} = build_actor(conn, authorizer)
      actor
    end

    @doc """
    Authorizes the conn's actor (built now from the current conn) for `rule`, for a
    resource given as `value:`. Returns `{:ok, conn}` (the conn unchanged) or
    `{:error, %Warden.Denial{}}`; sends no response.

        Warden.Plug.authorize(conn, check(:owner), value: post)
        Warden.Plug.authorize(conn, check(:owner), value: post, authorizer: MyApp.Authz)

    Options: `:value`; `:authorizer` (explicit option, then the configured default). An
    unknown role, permission or check raises `Warden.PolicyError`.
    """
    @spec authorize(Plug.Conn.t(), Rule.t(), keyword) ::
            {:ok, Plug.Conn.t()} | {:error, Denial.t()}
    def authorize(%Plug.Conn{} = conn, rule, opts \\ []) do
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
      {actor, context} = build_actor(conn, authorizer)

      case Warden.authorize(actor, rule,
             authorizer: authorizer,
             context: context,
             value: Keyword.get(opts, :value)
           ) do
        :ok -> {:ok, conn}
        {:error, denial} -> {:error, denial}
      end
    end

    @doc """
    Like `authorize/3`, but returns the conn or raises `Warden.ForbiddenError` (which
    Phoenix renders as 403). Same options as `authorize/3`.

        conn = Warden.Plug.authorize!(conn, check(:owner), value: post)
        conn = Warden.Plug.authorize!(conn, check(:owner), value: post, authorizer: MyApp.Authz)
    """
    @spec authorize!(Plug.Conn.t(), Rule.t(), keyword) :: Plug.Conn.t()
    def authorize!(%Plug.Conn{} = conn, rule, opts \\ []) do
      case authorize(conn, rule, opts) do
        {:ok, conn} ->
          conn

        {:error, %Denial{} = denial} ->
          authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
          raise Warden.ForbiddenError.for_denial(denial, authorizer.__warden_catalog__())
      end
    end

    ## Internals

    # No cache: the actor always reflects the conn as it is now.
    defp build_actor(conn, authorizer) do
      context = conn_context(conn, authorizer)
      {Actor.build(authorizer, context), context}
    end

    defp conn_context(conn, authorizer) do
      if function_exported?(authorizer, :conn_context, 1) do
        case authorizer.conn_context(conn) do
          context when is_map(context) ->
            context

          other ->
            raise Warden.PolicyError,
                  "#{inspect(authorizer)}.conn_context/1 must return a map, got: #{inspect(other)}"
        end
      else
        Map.put(conn.assigns, :conn, conn)
      end
    end

    defp deny(conn, denial, %{authorizer: authorizer, on_deny: on_deny}) do
      result =
        cond do
          on_deny != nil ->
            {mod, fun} = on_deny
            apply(mod, fun, [conn, denial])

          function_exported?(authorizer, :deny_conn, 2) ->
            authorizer.deny_conn(conn, denial)

          true ->
            default_response(conn, denial)
        end

      # A handler that returns something other than a conn is ignored.
      conn =
        case result do
          %Plug.Conn{} = handled -> handled
          _ -> conn
        end

      conn =
        case conn.state do
          :unset -> default_response(conn, denial)
          :set -> send_resp(conn)
          _sent -> conn
        end

      halt(conn)
    end

    defp default_response(conn, %Denial{actor: actor}) do
      {status, body} =
        case actor do
          %Actor{subject: nil} -> {401, "Unauthorized"}
          _ -> {403, "Forbidden"}
        end

      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(status, body)
    end
  end
end
