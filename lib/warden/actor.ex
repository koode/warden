defmodule Warden.Actor do
  @moduledoc """
  The identity a request is authorized as.

  `roles` holds the actor's roles after hierarchy expansion. `permissions` holds the
  permissions granted by `role_permissions` merged with `c:Warden.Authorizer.permissions/2`.
  A role mapped to `:all` in `role_permissions` adds the `:all` marker to `permissions`,
  which grants every permission (never a role).

  `authorizer` is the authorizer module that built the actor. The core API refuses an
  actor built by a different authorizer than the one it is asked to use.

  In GraphQL the actor is built once per document execution and cached in
  `resolution.acc`. `Warden.Plug` builds it on every check, from the current conn; there
  is no conn cache.

  `inspect/1` shows the authorizer, kind, roles, permissions, the credential method and
  scopes, whether the actor is anonymous or a system actor, and the delegator's kind.
  Never the subject and never the bounds. `actor.subject` (and `Map.from_struct/1`) still
  expose them.

  ## Kinds, credentials and system actors

    * `kind` - what the actor is: `:user` by default, a declared kind returned by
      `c:Warden.Authorizer.kind/2`, `:anonymous` for an actor without a subject, or the
      kind of a system actor.
    * `credential` - a `Warden.Credential` from `c:Warden.Authorizer.credential/1`, or
      `nil` for a full session.
    * `system?` - `true` for actors built with `Warden.system_actor/2` (webhooks, jobs).
      A system actor is never anonymous and never a user: it passes no role, tenant role,
      permission, `authenticated()` or check rule that does not name its kind.
    * `delegator` - for an actor acting on behalf of another (`Warden.on_behalf_of/3`),
      that other actor. Every rule is evaluated for both and ANDed.
    * `bounds` - a map Warden does not read, for policies: the credential's bounds, the
      bounds of a system actor, plus the bounds given to `Warden.on_behalf_of/3`.
    * `cache` - private. The tenant roles and tenants already read. It lives only in
      this struct, so it never outlives the actor.
    * `context` - private. The context the actor was built from. The core API, the Ecto
      layer and every other function given an actor without `context:` give checks and
      policies this context. Never shown by `inspect/1`.
  """

  alias Warden.Authorizer.Callbacks
  alias Warden.{Credential, Shape}

  require Logger

  @type t :: %__MODULE__{
          subject: term,
          roles: MapSet.t(atom),
          permissions: MapSet.t(term),
          authorizer: module | nil,
          kind: atom,
          credential: Credential.t() | nil,
          system?: boolean,
          delegator: t | nil,
          bounds: map,
          cache: map,
          context: map | nil
        }

  @anonymous_kind :anonymous
  @nested_delegation """
  does not take an actor that already acts on behalf of another, on either side: \
  delegation is one level deep\
  """
  @default_kind :user

  defstruct subject: nil,
            roles: MapSet.new(),
            permissions: MapSet.new(),
            authorizer: nil,
            kind: @anonymous_kind,
            credential: nil,
            system?: false,
            delegator: nil,
            bounds: %{},
            cache: %{},
            context: nil

  @doc "Returns true when the actor has no subject and is not a system actor."
  @spec anonymous?(t) :: boolean
  def anonymous?(%__MODULE__{system?: true}), do: false
  def anonymous?(%__MODULE__{subject: nil}), do: true
  def anonymous?(%__MODULE__{}), do: false

  @doc """
  Returns the actor's kind: the system actor's kind, `:anonymous` without a subject, else
  the kind `c:Warden.Authorizer.kind/2` returned (`:user` by default).
  """
  @spec kind(t) :: atom
  def kind(%__MODULE__{system?: true, kind: kind}), do: kind
  def kind(%__MODULE__{subject: nil}), do: @anonymous_kind
  def kind(%__MODULE__{kind: @anonymous_kind}), do: @default_kind
  def kind(%__MODULE__{kind: kind}), do: kind

  @doc "Returns the tenant the actor's credential is bound to, or `nil`."
  @spec bound_tenant(t) :: term
  def bound_tenant(%__MODULE__{credential: %Credential{tenant: tenant}}), do: tenant
  def bound_tenant(%__MODULE__{}), do: nil

  @doc """
  Returns true when the actor may act in `tenant` at all: its credential is not bound, or
  is bound to `tenant`. Policies and scopes for any other tenant are `false`.
  """
  @spec tenant_allowed?(t, term) :: boolean
  def tenant_allowed?(%__MODULE__{} = actor, tenant) do
    case bound_tenant(actor) do
      nil -> true
      bound -> bound == tenant
    end
  end

  @doc "Returns true when the actor holds every permission (`:all` marker)."
  @spec all_permissions?(t) :: boolean
  def all_permissions?(%__MODULE__{permissions: perms}), do: MapSet.member?(perms, :all)

  @doc """
  Builds the actor for `context` through `authorizer`.

  An anonymous subject (`nil` or `false`) gets no roles and no permissions; the
  `roles/2` and `permissions/2` callbacks are not called for it. A subject of `:error`
  or `{:error, _}` raises `Warden.PolicyError`.
  """
  @spec build(module, map) :: t
  def build(authorizer, context) do
    catalog = authorizer.__warden_catalog__()

    case authorizer.subject(context) do
      # `false` is a common "no user" value; it is anonymous, never a subject.
      anonymous when anonymous in [nil, false] ->
        %__MODULE__{authorizer: authorizer, kind: @anonymous_kind, context: context}

      # A failed lookup is a bug in subject/1 (or an unhandled error), not a user.
      failed when failed == :error or (is_tuple(failed) and elem(failed, 0) == :error) ->
        raise Warden.PolicyError,
              "#{inspect(authorizer)}.subject/1 returned #{failure_shape(failed)}; return the " <>
                "subject, or nil (or false) for an anonymous actor"

      subject ->
        roles =
          subject
          |> authorizer.roles(context)
          |> ensure_list!(authorizer, :roles)
          |> known_roles(catalog, authorizer)
          |> expand_roles(catalog)

        perms =
          subject
          |> then(&Callbacks.permissions(authorizer, &1, context))
          |> ensure_list!(authorizer, :permissions)
          |> known_permissions(catalog, authorizer)

        perms = MapSet.union(MapSet.new(perms), role_permissions(roles, catalog))
        kind = kind!(authorizer, subject, context, catalog)
        credential = credential!(authorizer, context, catalog)

        %__MODULE__{
          subject: subject,
          roles: roles,
          permissions: perms,
          authorizer: authorizer,
          kind: kind,
          credential: credential,
          bounds: credential_bounds(credential),
          context: context
        }
    end
  end

  @doc """
  Builds a system actor (see `Warden.system_actor/2`, which resolves the authorizer).
  """
  @spec system(module, keyword) :: t
  def system(authorizer, opts) when is_atom(authorizer) and is_list(opts) do
    catalog = authorizer.__warden_catalog__()

    case Keyword.keys(opts) -- [:kind, :tenant, :bounds, :reason] do
      [] -> :ok
      unknown -> raise ArgumentError, "unknown Warden.system_actor/2 options: #{inspect(unknown)}"
    end

    kind = Keyword.get(opts, :kind)
    bounds = Keyword.get(opts, :bounds, %{})
    reason = Keyword.get(opts, :reason)

    if kind == @default_kind or not MapSet.member?(catalog.kinds, kind) do
      raise ArgumentError, """
      Warden.system_actor/2 needs `kind:`, a kind declared in #{inspect(authorizer)}'s \
      `kinds:` other than :user, got: #{inspect(kind)}\
      """
    end

    if not is_map(bounds), do: raise(ArgumentError, "system actor `bounds:` must be a map")
    if not is_atom(reason), do: raise(ArgumentError, "system actor `reason:` must be an atom")

    credential = %Credential{
      method: :system,
      scopes: [],
      tenant: Keyword.get(opts, :tenant),
      bounds: bounds,
      reason: reason
    }

    %__MODULE__{
      authorizer: authorizer,
      kind: kind,
      system?: true,
      credential: credential,
      bounds: bounds
    }
  end

  @doc """
  Returns `actor` acting on behalf of `delegator` (see `Warden.on_behalf_of/3`).
  """
  @spec delegate(t, t, keyword) :: t
  def delegate(%__MODULE__{} = actor, %__MODULE__{} = delegator, opts) when is_list(opts) do
    bounds = Keyword.get(opts, :bounds, %{})

    case delegation_error(actor, delegator, opts, bounds) do
      nil -> %{actor | delegator: delegator, bounds: narrow_bounds(actor.bounds, bounds)}
      message -> raise ArgumentError, "Warden.on_behalf_of/3 " <> message
    end
  end

  def delegate(actor, delegator, _opts) do
    raise ArgumentError, """
    Warden.on_behalf_of/3 needs two %Warden.Actor{}s, got: #{Shape.describe(actor)} and \
    #{Shape.describe(delegator)}\
    """
  end

  # Delegation bounds only narrow the actor's own bounds (its credential's included): for
  # a key in both, two lists give their intersection, equal values stay, and differing
  # values of any other kind raise. A key in only one of them is kept.
  defp narrow_bounds(own, given) do
    Enum.reduce(given, own, fn {key, value}, bounds ->
      case Map.fetch(bounds, key) do
        :error -> Map.put(bounds, key, value)
        {:ok, ^value} -> bounds
        {:ok, existing} -> Map.put(bounds, key, intersect_bound!(key, existing, value))
      end
    end)
  end

  defp intersect_bound!(_key, existing, given) when is_list(existing) and is_list(given),
    do: Enum.filter(existing, &(&1 in given))

  defp intersect_bound!(key, _existing, _given) do
    raise ArgumentError, """
    Warden.on_behalf_of/3 `bounds:` gives #{inspect(key)} a value that differs from the \
    actor's own; only lists can be narrowed (to their intersection)\
    """
  end

  defp delegation_error(actor, delegator, opts, bounds) do
    cond do
      Keyword.keys(opts) -- [:bounds] != [] -> "only takes `bounds:`"
      not is_map(bounds) -> "`bounds:` must be a map"
      not same_authorizer?(actor, delegator) -> "needs two actors built by the same authorizer"
      anonymous?(actor) or anonymous?(delegator) -> "does not take anonymous actors"
      actor.delegator != nil or delegator.delegator != nil -> @nested_delegation
      true -> nil
    end
  end

  defp same_authorizer?(actor, delegator),
    do: actor.authorizer != nil and actor.authorizer == delegator.authorizer

  @doc """
  Returns the actor's tenant roles in `tenant` (after `tenant_role_hierarchy`) and the
  actor with them cached. `c:Warden.Authorizer.tenant_roles/3` runs at most once per
  actor and tenant. An anonymous or system actor, a `nil` tenant and a tenant other than
  the one the credential is bound to have no tenant roles, and the callback is not called.
  """
  @spec tenant_roles(t, term, map) :: {MapSet.t(atom), t}
  def tenant_roles(%__MODULE__{authorizer: authorizer} = actor, tenant, context) do
    tenant_roles(actor, tenant, context, authorizer)
  end

  @doc false
  @spec tenant_roles(t, term, map, module) :: {MapSet.t(atom), t}
  def tenant_roles(%__MODULE__{} = actor, tenant, context, authorizer) do
    cond do
      tenant == nil or actor.system? or anonymous?(actor) or
          not tenant_allowed?(actor, tenant) ->
        {MapSet.new(), actor}

      Map.has_key?(actor.cache, {:tenant_roles, tenant}) ->
        {Map.fetch!(actor.cache, {:tenant_roles, tenant}), actor}

      true ->
        roles = load_tenant_roles(actor, tenant, context, authorizer)
        cache = Map.put(actor.cache, {:tenant_roles, tenant}, roles)
        {roles, %{actor | cache: cache}}
    end
  end

  @doc """
  Reads the tenant roles for every tenant in `tenants` that is not cached yet and returns
  the actor with them cached. Pass the returned actor to later calls so they do not read
  the roles again.
  """
  @spec preload_tenant_roles(t, [term], map) :: t
  def preload_tenant_roles(%__MODULE__{} = actor, tenants, context) when is_list(tenants) do
    Enum.reduce(tenants, actor, fn tenant, acc ->
      {_roles, loaded} = tenant_roles(acc, tenant, context)
      loaded
    end)
  end

  @doc """
  Returns the tenants the actor may act in, from `c:Warden.Authorizer.tenants/2`
  (default: none). A bound credential narrows the list to its tenant; a delegated actor
  acts only in tenants both actors have. An anonymous actor has none; a system actor has
  only the tenant it is bound to. Reads the actor's cache when `cached_tenants/2` filled
  it; see that function to keep the result.
  """
  @spec tenants(t, map) :: [term]
  def tenants(%__MODULE__{} = actor, context) do
    {tenants, _actor} = cached_tenants(actor, context)
    tenants
  end

  @doc """
  Like `tenants/2`, but returns the actor with its own tenant list cached, so
  `c:Warden.Authorizer.tenants/2` runs at most once per actor (and once for its
  delegator).
  """
  @spec cached_tenants(t, map) :: {[term], t}
  def cached_tenants(%__MODULE__{} = actor, context) do
    {own, actor} = own_tenants(actor, context)

    case actor.delegator do
      nil ->
        {own, actor}

      %__MODULE__{} = delegator ->
        {shared, delegator} = cached_tenants(delegator, context)
        both = Enum.filter(own, &(&1 in shared))
        {both, %{actor | delegator: delegator}}
    end
  end

  # The actor's own tenants, before the delegator narrows them: what the callback lists
  # for its subject, narrowed to a bound credential's tenant. Cached under :tenants.
  defp own_tenants(%__MODULE__{cache: %{tenants: tenants}} = actor, _context),
    do: {tenants, actor}

  defp own_tenants(%__MODULE__{authorizer: authorizer} = actor, context) do
    tenants =
      cond do
        anonymous?(actor) ->
          []

        actor.system? ->
          List.wrap(bound_tenant(actor))

        true ->
          authorizer
          |> Callbacks.tenants(%{actor | delegator: nil}, context)
          |> narrow_to_bound(bound_tenant(actor))
      end

    {tenants, %{actor | cache: Map.put(actor.cache, :tenants, tenants)}}
  end

  defp narrow_to_bound(listed, nil), do: listed
  defp narrow_to_bound(listed, bound), do: Enum.filter(listed, &(&1 == bound))

  defp load_tenant_roles(actor, tenant, context, authorizer) do
    catalog = authorizer.__warden_catalog__()

    if catalog.tenant_roles == nil do
      MapSet.new()
    else
      authorizer
      |> Callbacks.tenant_roles(actor.subject, tenant, context)
      |> ensure_list!(authorizer, :tenant_roles, 3)
      |> known_tenant_roles(catalog, authorizer)
      |> Enum.reduce(MapSet.new(), fn role, acc ->
        MapSet.union(acc, Map.fetch!(catalog.implied_tenant_roles, role))
      end)
    end
  end

  defp known_tenant_roles(roles, catalog, authorizer) do
    {known, unknown} = Enum.split_with(roles, &MapSet.member?(catalog.tenant_roles, &1))

    if unknown != [] do
      Logger.warning("""
      Warden: #{inspect(authorizer)}.tenant_roles/3 returned roles that are not in the \
      tenant role catalog; they were dropped: #{inspect(Enum.uniq(unknown))}\
      """)
    end

    known
  end

  defp kind!(authorizer, subject, context, catalog) do
    case Callbacks.kind(authorizer, subject, context) do
      kind when is_atom(kind) and kind != @anonymous_kind ->
        if MapSet.member?(catalog.kinds, kind), do: kind, else: undeclared_kind!(authorizer, kind)

      other ->
        undeclared_kind!(authorizer, other)
    end
  end

  # A failed lookup is printed only as far as it carries no data: `:error` and an error
  # with an atom reason as they are, anything else by its shape.
  defp failure_shape(:error), do: ":error"
  defp failure_shape({:error, reason} = failed) when is_atom(reason), do: inspect(failed)
  defp failure_shape(failed), do: Shape.describe(failed)

  defp kind_shape(kind) when is_atom(kind), do: inspect(kind)
  defp kind_shape(kind), do: Shape.describe(kind)

  @spec undeclared_kind!(module, term) :: no_return()
  defp undeclared_kind!(authorizer, kind) do
    raise Warden.PolicyError, """
    #{inspect(authorizer)}.kind/2 returned #{kind_shape(kind)}, which is not a kind in its \
    `kinds:` catalog\
    """
  end

  defp credential!(authorizer, context, catalog) do
    case Callbacks.credential(authorizer, context) do
      nil ->
        nil

      %Credential{} = credential ->
        credential
        |> validate_credential!(authorizer)
        |> known_scopes(catalog, authorizer)

      other ->
        raise Warden.PolicyError, """
        #{inspect(authorizer)}.credential/1 must return a %Warden.Credential{} or nil, \
        got: #{Shape.describe(other)}\
        """
    end
  end

  defp validate_credential!(%Credential{} = credential, authorizer) do
    valid? =
      is_atom(credential.method) and credential.method != nil and is_map(credential.bounds) and
        (credential.scopes == :all or
           (is_list(credential.scopes) and Enum.all?(credential.scopes, &is_binary/1)))

    if valid? do
      credential
    else
      raise Warden.PolicyError, """
      #{inspect(authorizer)}.credential/1 returned an invalid credential: `method` must be \
      an atom, `scopes` a list of strings or :all, `bounds` a map\
      """
    end
  end

  defp known_scopes(%Credential{scopes: :all} = credential, _catalog, _authorizer),
    do: credential

  defp known_scopes(credential, %{credential_scopes: nil}, _authorizer), do: credential

  defp known_scopes(credential, catalog, authorizer) do
    {known, unknown} =
      Enum.split_with(credential.scopes, &MapSet.member?(catalog.credential_scopes, &1))

    if unknown != [] do
      Logger.warning("""
      Warden: #{inspect(authorizer)}.credential/1 returned scopes that are not in the \
      credential scope catalog; they were dropped: #{inspect(Enum.uniq(unknown))}\
      """)
    end

    %{credential | scopes: known}
  end

  defp credential_bounds(nil), do: %{}
  defp credential_bounds(%Credential{bounds: bounds}), do: bounds

  defp ensure_list!(list, authorizer, callback, arity \\ 2)

  defp ensure_list!(list, _authorizer, _callback, _arity) when is_list(list), do: list

  defp ensure_list!(other, authorizer, callback, arity) do
    raise Warden.PolicyError,
          "#{inspect(authorizer)}.#{callback}/#{arity} must return a list, got: #{Shape.describe(other)}"
  end

  defp known_roles(roles, catalog, authorizer) do
    {known, unknown} = Enum.split_with(roles, &MapSet.member?(catalog.roles, &1))

    if unknown != [] do
      Logger.warning(
        "Warden: #{inspect(authorizer)}.roles/2 returned roles that are not in the catalog; " <>
          "they were dropped: #{inspect(Enum.uniq(unknown))}"
      )
    end

    known
  end

  defp known_permissions(perms, %{permissions: nil}, _authorizer) do
    Enum.reject(perms, &(&1 == :all))
  end

  defp known_permissions(perms, catalog, authorizer) do
    {known, unknown} = Enum.split_with(perms, &MapSet.member?(catalog.permissions, &1))

    if unknown != [] do
      Logger.warning(
        "Warden: #{inspect(authorizer)}.permissions/2 returned permissions that are not in " <>
          "the catalog; they were dropped: #{inspect(Enum.uniq(unknown))}"
      )
    end

    known
  end

  defp expand_roles(roles, catalog) do
    Enum.reduce(roles, MapSet.new(), fn role, acc ->
      MapSet.union(acc, Map.fetch!(catalog.implied_roles, role))
    end)
  end

  defp role_permissions(roles, catalog) do
    Enum.reduce(roles, MapSet.new(), fn role, acc ->
      case Map.get(catalog.role_permissions, role, []) do
        :all -> MapSet.put(acc, :all)
        perms -> MapSet.union(acc, MapSet.new(perms))
      end
    end)
  end
end

defimpl Inspect, for: Warden.Actor do
  # The subject is the user record (email, tokens, ...). Keep it out of logs and crash
  # reports; `actor.subject` stays available to code.
  import Inspect.Algebra

  def inspect(actor, opts) do
    fields = [
      authorizer: actor.authorizer,
      anonymous: Warden.Actor.anonymous?(actor),
      kind: Warden.Actor.kind(actor),
      system?: actor.system?,
      roles: actor.roles |> Enum.sort(),
      permissions: actor.permissions |> Enum.sort(),
      credential: credential_summary(actor.credential),
      delegator: delegator_kind(actor.delegator)
    ]

    concat(["#Warden.Actor<", to_doc(fields, opts), ">"])
  end

  defp credential_summary(nil), do: nil

  defp credential_summary(credential) do
    %{method: credential.method, scopes: credential.scopes}
  end

  defp delegator_kind(nil), do: nil
  defp delegator_kind(delegator), do: Warden.Actor.kind(delegator)
end
