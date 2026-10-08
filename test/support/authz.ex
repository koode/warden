defmodule Warden.Test.Authz do
  @moduledoc false
  use Warden.Authorizer,
    roles: [:admin, :editor, :viewer, :auditor],
    permissions: ["posts:read", "posts:write", "secrets:read", "users:list"],
    role_hierarchy: %{admin: [:editor], editor: [:viewer]},
    role_permissions: %{admin: :all, editor: ["posts:write", "posts:read"], viewer: ["posts:read"]},
    checks: [:self, :owner, :configured]

  @impl true
  def subject(context), do: context[:current_user]

  @impl true
  def roles(user, context) do
    # A test can make roles/2 read live data (for revocation tests) or break the
    # contract on purpose.
    case context[:roles_fun] do
      nil -> user.roles
      fun -> fun.(user)
    end
  end

  @impl true
  def permissions(user, _context), do: Map.get(user, :permissions, [])

  @impl true
  def check(:self, %Warden.Check{actor: actor, value: value}) do
    is_map(value) and Map.get(value, :id) == actor.subject.id
  end

  def check(:owner, %Warden.Check{actor: actor, value: value}) do
    is_map(value) and Map.get(value, :author_id) == actor.subject.id
  end

  # Returns whatever the test put in the context, to test non-boolean returns.
  def check(:configured, %Warden.Check{context: context}) do
    Map.get(context, :check_result, false)
  end
end

defmodule Warden.Test.Data do
  @moduledoc false

  def users do
    [
      %{kind: :user, id: "u1", name: "Alice", email: "alice@example.com", roles: [:admin]},
      %{kind: :user, id: "u2", name: "Bob", email: "bob@example.com", roles: [:viewer]},
      %{kind: :user, id: "u3", name: "Carol", email: "carol@example.com", roles: [:editor]},
      %{kind: :user, id: "u4", name: "Dan", email: "dan@example.com", roles: []}
    ]
  end

  def posts do
    [
      %{kind: :post, id: "p1", title: "Hello", author_id: "u2", draft_notes: "bob notes"},
      %{kind: :post, id: "p2", title: "World", author_id: "u3", draft_notes: "carol notes"}
    ]
  end

  def secrets do
    [
      %{kind: :secret, id: "s1", code: "ALPHA"},
      %{kind: :secret, id: "s2", code: "BRAVO"}
    ]
  end

  def all, do: users() ++ posts() ++ secrets()

  def get(id), do: Enum.find(all(), &(&1.id == id))
  def user(id), do: Enum.find(users(), &(&1.id == id))

  def as(role_or_roles, id \\ "u9") do
    %{id: id, name: "Tester", roles: List.wrap(role_or_roles)}
  end
end

defmodule Warden.Test.Probe do
  @moduledoc false
  # Resolvers call this so tests can assert which resolvers ran.
  def hit(%{context: %{test_pid: pid}}, tag) when is_pid(pid), do: send(pid, {:resolved, tag})
  def hit(_, _), do: :ok
end
