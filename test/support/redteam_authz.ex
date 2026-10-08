defmodule Warden.Redteam.Authz do
  @moduledoc false
  # Same catalog as Warden.Test.Authz, but checks are nil-safe for anonymous actors and
  # a test can override the denial handler by putting `deny_fun` in the user map.
  use Warden.Authorizer,
    roles: [:admin, :editor, :viewer, :auditor],
    permissions: ["posts:read", "posts:write", "secrets:read", "users:list"],
    role_hierarchy: %{admin: [:editor], editor: [:viewer]},
    role_permissions: %{
      admin: :all,
      editor: ["posts:write", "posts:read"],
      viewer: ["posts:read"]
    },
    checks: [:self, :owner]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, _context), do: user.roles

  @impl true
  def check(:self, %Warden.Check{actor: actor, value: value}) do
    actor.subject != nil and is_map(value) and Map.get(value, :id) == actor.subject.id
  end

  def check(:owner, %Warden.Check{actor: actor, value: value}) do
    actor.subject != nil and is_map(value) and Map.get(value, :author_id) == actor.subject.id
  end

  @impl true
  def deny(%Warden.Denial{actor: %{subject: %{deny_fun: fun}}} = denial)
      when is_function(fun, 1) do
    case fun.(denial) do
      :default -> Warden.Authorizer.default_deny(denial, __warden_catalog__())
      other -> other
    end
  end

  def deny(denial), do: Warden.Authorizer.default_deny(denial, __warden_catalog__())
end
