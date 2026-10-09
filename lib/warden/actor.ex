defmodule Warden.Actor do
  @moduledoc """
  The identity a request is authorized as.

  `roles` holds the actor's roles after hierarchy expansion. `permissions` holds the
  permissions granted by `role_permissions` merged with `c:Warden.Authorizer.permissions/2`.
  A role mapped to `:all` in `role_permissions` adds the `:all` marker to `permissions`,
  which grants every permission (never a role).

  The actor is built once per document execution and cached in `resolution.acc`.
  """

  require Logger

  @type t :: %__MODULE__{
          subject: term,
          roles: MapSet.t(atom),
          permissions: MapSet.t(term)
        }

  defstruct subject: nil, roles: MapSet.new(), permissions: MapSet.new()

  @doc "Returns true when the actor has no subject."
  @spec anonymous?(t) :: boolean
  def anonymous?(%__MODULE__{subject: nil}), do: true
  def anonymous?(%__MODULE__{}), do: false

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
        %__MODULE__{}

      # A failed lookup is a bug in subject/1 (or an unhandled error), not a user.
      failed when failed == :error or (is_tuple(failed) and elem(failed, 0) == :error) ->
        raise Warden.PolicyError,
              "#{inspect(authorizer)}.subject/1 returned #{inspect(failed)}; return the " <>
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
          |> authorizer.permissions(context)
          |> ensure_list!(authorizer, :permissions)
          |> known_permissions(catalog, authorizer)

        perms = MapSet.union(MapSet.new(perms), role_permissions(roles, catalog))

        %__MODULE__{subject: subject, roles: roles, permissions: perms}
    end
  end

  defp ensure_list!(list, _authorizer, _callback) when is_list(list), do: list

  defp ensure_list!(other, authorizer, callback) do
    raise Warden.PolicyError,
          "#{inspect(authorizer)}.#{callback}/2 must return a list, got: #{inspect(other)}"
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
