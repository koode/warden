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
        Overrides the authorizer's `c:Warden.Authorizer.deny_conn/2`.

    `init/1` resolves the authorizer and validates the rule against its catalog. Phoenix
    runs `init/1` at compile time, so an unknown role, permission or check, or a missing
    authorizer, fails compilation (`ArgumentError`).

    On denial the handler runs: `on_deny`, else the authorizer's `deny_conn/2`, else the
    default, which sends `401 Unauthorized` to an anonymous actor and `403 Forbidden`
    otherwise. Whatever the handler returns, the conn is halted, and when the handler sent
    no response the default response is sent. A handler cannot let a denied request
    through.

    ## In a controller

        with {:ok, conn} <- Warden.Plug.authorize(conn, check(:owner), value: post) do
          render(conn, :show, post: post)
        end

        conn = Warden.Plug.authorize!(conn, check(:owner), value: post, authorizer: MyApp.Authz)

    `authorize/3` returns `{:ok, conn}` or `{:error, %Warden.Denial{}}` and sends nothing;
    `authorize!/3` returns the conn or raises `Warden.ForbiddenError` (rendered as 403).
    Options: `:value`, and `:authorizer` (explicit option, then the configured default;
    there is no actor argument, the conn caches one actor per authorizer).

    ## The actor

    The actor is built once per conn, from `c:Warden.Authorizer.conn_context/1` (default
    `Map.put(conn.assigns, :conn, conn)`), and cached in `conn.private[:warden_actor]`,
    keyed by authorizer. Nothing is cached across requests or in the process dictionary.
    The actor reflects the assigns at the first Warden check of the request; run your
    authentication plug before the first Warden plug.
    """

    @behaviour Plug

    import Plug.Conn

    alias Warden.{Actor, Denial, Rule}

    @private_key :warden_actor
    @option_keys [:rule, :authorizer, :on_deny]

    @typedoc "The compiled plug options."
    @type config :: %{rule: Rule.t(), authorizer: module, on_deny: nil | {module, atom}}

    @impl Plug
    @spec init(keyword) :: config
    def init(opts) when is_list(opts) do
      unknown = Keyword.keys(opts) -- @option_keys

      if unknown != [] do
        raise ArgumentError, "unknown Warden.Plug options: #{inspect(unknown)}"
      end

      rule =
        case Keyword.fetch(opts, :rule) do
          {:ok, rule} -> rule
          :error -> raise ArgumentError, "Warden.Plug needs a `rule:` option"
        end

      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))

      case Rule.validate(rule, authorizer.__warden_catalog__()) do
        :ok ->
          :ok

        {:error, errors} ->
          raise ArgumentError,
                "invalid Warden.Plug rule for #{inspect(authorizer)}: " <> Enum.join(errors, "; ")
      end

      on_deny =
        case Keyword.get(opts, :on_deny) do
          nil ->
            nil

          {mod, fun} = handler when is_atom(mod) and is_atom(fun) ->
            handler

          other ->
            raise ArgumentError,
                  "Warden.Plug `on_deny:` must be {module, function}, got: #{inspect(other)}"
        end

      %{rule: rule, authorizer: authorizer, on_deny: on_deny}
    end

    @impl Plug
    @spec call(Plug.Conn.t(), config) :: Plug.Conn.t()
    def call(conn, %{rule: rule, authorizer: authorizer} = config) do
      {conn, actor, context} = fetch_actor(conn, authorizer)

      case Warden.authorize(actor, rule, authorizer: authorizer, context: context) do
        :ok -> conn
        {:error, denial} -> deny(conn, denial, config)
      end
    end

    @doc """
    Returns `{conn, actor}`: the actor for the conn, built once and cached in the conn.
    Option `:authorizer`: explicit option, else the configured default.
    """
    @spec actor(Plug.Conn.t(), keyword) :: {Plug.Conn.t(), Actor.t()}
    def actor(%Plug.Conn{} = conn, opts \\ []) do
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
      {conn, actor, _context} = fetch_actor(conn, authorizer)
      {conn, actor}
    end

    @doc """
    Authorizes the conn's actor for `rule`, for a resource given as `value:`. Returns
    `{:ok, conn}` (with the actor cached) or `{:error, %Warden.Denial{}}`; sends no
    response.

        Warden.Plug.authorize(conn, check(:owner), value: post)
        Warden.Plug.authorize(conn, check(:owner), value: post, authorizer: MyApp.Authz)

    Options: `:value`; `:authorizer` (explicit option, then the configured default; the
    conn caches one actor per authorizer). An unknown role, permission or check raises
    `Warden.PolicyError`.
    """
    @spec authorize(Plug.Conn.t(), Rule.t(), keyword) ::
            {:ok, Plug.Conn.t()} | {:error, Denial.t()}
    def authorize(%Plug.Conn{} = conn, rule, opts \\ []) do
      authorizer = Warden.resolve_authorizer!(Keyword.get(opts, :authorizer))
      {conn, actor, context} = fetch_actor(conn, authorizer)

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

    defp fetch_actor(conn, authorizer) do
      context = conn_context(conn, authorizer)
      cache = Map.get(conn.private, @private_key, %{})

      case cache do
        %{^authorizer => %Actor{} = actor} ->
          {conn, actor, context}

        _ ->
          actor = Actor.build(authorizer, context)
          {put_private(conn, @private_key, Map.put(cache, authorizer, actor)), actor, context}
      end
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
        if match?(%Actor{}, actor) and Actor.anonymous?(actor),
          do: {401, "Unauthorized"},
          else: {403, "Forbidden"}

      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(status, body)
    end
  end
end
