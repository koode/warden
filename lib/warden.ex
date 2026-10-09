defmodule Warden do
  @moduledoc """
  Role- and permission-based authorization for Elixir. One authorizer module serves
  every front end:

    * the core API in this module, for any Elixir code (controllers, contexts, jobs);
    * `Warden.Plug`, for Plug and Phoenix (needs `plug`);
    * `Warden.Absinthe`, for Absinthe GraphQL schemas (needs `absinthe`).

  Building blocks: `Warden.Authorizer` (the behaviour for your authorizer module),
  `Warden.Rule` (the rule builders), `Warden.Actor`, `Warden.Check`, `Warden.Denial`,
  `Warden.PolicyError` and `Warden.ForbiddenError`.

  ## Choosing the authorizer

  Every entry point takes the authorizer in one of two first-class ways:

      # 1. Explicitly, with the `authorizer:` option:
      Warden.authorize(context, role(:admin), authorizer: MyApp.Authz)

      # 2. From the configured default (config/config.exs):
      #    config :warden, authorizer: MyApp.Authz
      Warden.authorize(context, role(:admin))

  Resolution order, the same in every layer (`resolve_authorizer!/2`):

    1. the explicit `authorizer:` option;
    2. the actor's own authorizer, when the first argument is a `%Warden.Actor{}` (an
       explicit option that names a different module raises `Warden.PolicyError`);
    3. the configured default, read with `Application.compile_env(:warden, :authorizer)`.

  With none of these, an `ArgumentError` names the fix. A module that does not
  `use Warden.Authorizer` raises an `ArgumentError` too.

  ## Core API

      import Warden.Rule

      actor = Warden.actor(context)                                   # default authorizer
      actor = Warden.actor(context, authorizer: MyApp.Authz)          # explicit

      :ok = Warden.authorize(actor, check(:owner), value: post)
      {:error, %Warden.Denial{kind: :call}} = Warden.authorize(context, role(:admin))
      Warden.allowed?(actor, role(:admin))                            # boolean
      Warden.authorize!(context, role(:admin), authorizer: MyApp.Authz) # or raises ForbiddenError
      Warden.filter(actor, check(:owner), posts)                      # permitted posts only

  `actor_or_context` is a `%Warden.Actor{}` (built once per request with `actor/2`) or a
  context map, from which the actor is built with the authorizer's callbacks (the same
  ones GraphQL uses).

  The rule is validated against the authorizer's catalog on every call; an unknown role,
  permission or check raises `Warden.PolicyError` (fail closed, never a silent deny).
  Evaluation is the same as in GraphQL: only a literal `true` from a check grants.

  See the README for the security model and its limits.
  """

  alias Warden.{Actor, Check, Denial, Rule}

  @default_authorizer Application.compile_env(:warden, :authorizer)

  @typedoc "A `%Warden.Actor{}` or a context map to build one from."
  @type actor_or_context :: Actor.t() | map

  @typedoc """
  Options:

    * `:authorizer` - the authorizer module. Resolution order: this option, then the
      actor's own authorizer, then the configured default.
    * `:value` - the resource the rule guards, given to checks as `Warden.Check.value`.
    * `:context` - the context given to checks as `Warden.Check.context` when the first
      argument is an actor (with a context map, that map is the context).
  """
  @type opts :: [authorizer: module, value: term, context: map]

  ## Authorizer resolution

  @doc """
  Returns the authorizer to use: the explicit `authorizer` (an option value or `nil`),
  else the authorizer of `actor` (an `%Warden.Actor{}` or `nil`), else the configured
  default (`config :warden, authorizer: MyApp.Authz`).

  Raises `Warden.PolicyError` when an explicit authorizer differs from the actor's, and
  `ArgumentError` when there is no authorizer or it does not `use Warden.Authorizer`.
  """
  @spec resolve_authorizer!(module | nil, Actor.t() | nil) :: module
  def resolve_authorizer!(explicit, actor \\ nil) do
    actor_authorizer =
      case actor do
        %Actor{authorizer: authorizer} -> authorizer
        _ -> nil
      end

    resolve_authorizer!(explicit, actor_authorizer, @default_authorizer)
  end

  @doc false
  # The resolution itself, with the default as an argument so every branch is testable.
  @spec resolve_authorizer!(module | nil, module | nil, module | nil) :: module
  def resolve_authorizer!(explicit, actor_authorizer, default) do
    authorizer =
      cond do
        explicit != nil and actor_authorizer != nil and explicit != actor_authorizer ->
          raise Warden.PolicyError,
                "the actor was built by #{inspect(actor_authorizer)}, but the call asks for " <>
                  "#{inspect(explicit)}; build the actor with the authorizer you check with"

        explicit != nil ->
          explicit

        actor_authorizer != nil ->
          actor_authorizer

        default != nil ->
          default

        true ->
          raise ArgumentError,
                "no Warden authorizer: pass `authorizer: MyApp.Authz`, or configure a " <>
                  "default in config/config.exs: `config :warden, authorizer: MyApp.Authz`"
      end

    ensure_authorizer!(authorizer)
  end

  @doc "Returns the configured default authorizer, or `nil`."
  @spec default_authorizer() :: module | nil
  def default_authorizer, do: @default_authorizer

  defp ensure_authorizer!(authorizer) when is_atom(authorizer) do
    if match?({:module, _}, Code.ensure_compiled(authorizer)) and
         function_exported?(authorizer, :__warden_catalog__, 0) do
      authorizer
    else
      raise ArgumentError,
            "#{inspect(authorizer)} is not a Warden authorizer: it must `use Warden.Authorizer`"
    end
  end

  defp ensure_authorizer!(other) do
    raise ArgumentError, "a Warden authorizer must be a module, got: #{inspect(other)}"
  end

  ## Core API

  @doc """
  Builds the actor for `context` (a map) through the authorizer. Build it once per
  request and pass it to the other functions.

      Warden.actor(%{current_user: user})                          # configured default
      Warden.actor(%{current_user: user}, authorizer: MyApp.Authz) # explicit

  Option `:authorizer`: explicit option, else the configured default.
  """
  @spec actor(map, keyword) :: Actor.t()
  def actor(context, opts \\ []) when is_map(context) and is_list(opts) do
    authorizer = resolve_authorizer!(opts[:authorizer], nil)
    Actor.build(authorizer, context)
  end

  @doc """
  Authorizes `actor_or_context` for `rule`. Returns `:ok` or
  `{:error, %Warden.Denial{kind: :call}}`.

      Warden.authorize(actor, check(:owner), value: post)
      Warden.authorize(context, role(:admin), authorizer: MyApp.Authz)

  Options: `:authorizer` (explicit option, then the actor's own authorizer, then the
  configured default), `:value`, `:context` (see `t:opts/0`).

  An unknown role, permission or check in `rule` raises `Warden.PolicyError`.
  """
  @spec authorize(actor_or_context, Rule.t(), opts) :: :ok | {:error, Denial.t()}
  def authorize(actor_or_context, rule, opts \\ []) when is_list(opts) do
    {actor, context, authorizer} = setup(actor_or_context, opts)
    validate_rule!(rule, authorizer)
    evaluate(rule, actor, context, authorizer, Keyword.get(opts, :value))
  end

  @doc """
  Returns `true` when `actor_or_context` passes `rule`, else `false`. Same options as
  `authorize/3` (`:authorizer` resolves as explicit option, actor's authorizer, configured
  default).

      Warden.allowed?(actor, role(:admin))
      Warden.allowed?(context, role(:admin), authorizer: MyApp.Authz)
  """
  @spec allowed?(actor_or_context, Rule.t(), opts) :: boolean
  def allowed?(actor_or_context, rule, opts \\ []),
    do: authorize(actor_or_context, rule, opts) == :ok

  @doc """
  Like `authorize/3`, but returns `:ok` or raises `Warden.ForbiddenError` (which Phoenix
  renders as 403). Same options as `authorize/3`.

      Warden.authorize!(actor, check(:owner), value: post)
      Warden.authorize!(context, role(:admin), authorizer: MyApp.Authz)
  """
  @spec authorize!(actor_or_context, Rule.t(), opts) :: :ok
  def authorize!(actor_or_context, rule, opts \\ []) when is_list(opts) do
    {actor, context, authorizer} = setup(actor_or_context, opts)
    validate_rule!(rule, authorizer)

    case evaluate(rule, actor, context, authorizer, Keyword.get(opts, :value)) do
      :ok ->
        :ok

      {:error, denial} ->
        raise Warden.ForbiddenError.for_denial(denial, authorizer.__warden_catalog__())
    end
  end

  @doc """
  Returns the values in `values` that `actor_or_context` may see under `rule`, in order.
  Each value is given to checks as `Warden.Check.value`. The actor is built and the rule
  validated once.

      Warden.filter(actor, check(:owner), posts)
      Warden.filter(context, check(:owner), posts, authorizer: MyApp.Authz)

  Options: `:authorizer` (explicit option, then the actor's own authorizer, then the
  configured default) and `:context`.
  """
  @spec filter(actor_or_context, Rule.t(), Enumerable.t(), opts) :: list
  def filter(actor_or_context, rule, values, opts \\ []) when is_list(opts) do
    {actor, context, authorizer} = setup(actor_or_context, opts)
    validate_rule!(rule, authorizer)
    Enum.filter(values, &(evaluate(rule, actor, context, authorizer, &1) == :ok))
  end

  ## Helpers

  defp setup(%Actor{} = actor, opts) do
    authorizer = resolve_authorizer!(opts[:authorizer], actor)
    {actor, Keyword.get(opts, :context, %{}), authorizer}
  end

  defp setup(context, opts) when is_map(context) do
    authorizer = resolve_authorizer!(opts[:authorizer], nil)
    {Actor.build(authorizer, context), context, authorizer}
  end

  defp setup(other, _opts) do
    raise ArgumentError, "expected a %Warden.Actor{} or a context map, got: #{inspect(other)}"
  end

  defp validate_rule!(rule, authorizer) do
    case Rule.validate(rule, authorizer.__warden_catalog__()) do
      :ok ->
        :ok

      {:error, errors} ->
        raise Warden.PolicyError,
              "invalid rule for #{inspect(authorizer)}: " <> Enum.join(errors, "; ")
    end
  end

  defp evaluate(rule, actor, context, authorizer, value) do
    check = %Check{actor: actor, value: value, context: context}

    case Rule.evaluate(rule, check, authorizer) do
      :ok ->
        :ok

      {:deny, failure} ->
        {:error,
         %Denial{
           kind: :call,
           rule: rule,
           failed_rule: failure.failed_rule,
           missing_roles: failure.missing_roles,
           missing_permissions: failure.missing_permissions,
           actor: actor
         }}
    end
  end
end
