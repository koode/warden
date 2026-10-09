defmodule Warden.CoreApiTest do
  @moduledoc """
  The core API, run through `Warden.Test.Authz`: the same authorizer module the Absinthe
  tests use (and the configured default in config/test.exs). One module serves both.
  """
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.Helpers, only: [run: 2]

  alias Warden.{Actor, Denial, ForbiddenError, PolicyError}
  alias Warden.Test.{Authz, Data}

  defmodule OtherAuthz do
    @moduledoc false
    use Warden.Authorizer, roles: [:admin], expose_denial_reasons: true

    @impl true
    def subject(ctx), do: ctx[:current_user]

    @impl true
    def roles(user, _), do: user.roles
  end

  defp ctx(user), do: %{current_user: user}
  defp admin, do: %{id: "u1", roles: [:admin]}
  defp viewer, do: %{id: "u2", roles: [:viewer]}

  describe "actor/2" do
    test "builds with the configured default" do
      actor = Warden.actor(ctx(admin()))
      assert %Actor{authorizer: Authz} = actor
      assert MapSet.member?(actor.roles, :viewer)
    end

    test "builds with an explicit authorizer" do
      assert %Actor{authorizer: OtherAuthz} = Warden.actor(ctx(admin()), authorizer: OtherAuthz)
    end
  end

  describe "authorize/3" do
    test "with a context map and the default authorizer" do
      assert Warden.authorize(ctx(admin()), role(:admin)) == :ok

      assert {:error, %Denial{kind: :call, rule: {:role, :admin}, missing_roles: [:admin]}} =
               Warden.authorize(ctx(viewer()), role(:admin))
    end

    test "with an actor and an explicit authorizer" do
      actor = Warden.actor(ctx(admin()), authorizer: OtherAuthz)
      assert Warden.authorize(actor, role(:admin), authorizer: OtherAuthz) == :ok
    end

    test "checks get the value and the context" do
      assert Warden.authorize(ctx(viewer()), check(:self), value: %{id: "u2"}) == :ok
      assert {:error, _} = Warden.authorize(ctx(viewer()), check(:self), value: %{id: "u1"})

      actor = Warden.actor(ctx(viewer()))
      assert Warden.authorize(actor, check(:configured), context: %{check_result: true}) == :ok
      assert {:error, _} = Warden.authorize(actor, check(:configured))
    end

    test "only a literal true from a check grants" do
      for bad <- [:ok, {:ok, true}, "yes", 1, nil] do
        assert_raise PolicyError, fn ->
          Warden.authorize(ctx(viewer()) |> Map.put(:check_result, bad), check(:configured))
        end
      end
    end

    test "the rule is validated against the catalog on every call" do
      for rule <- [role(:ghost), permission("nope"), check(:nope), {:not, :public}] do
        assert_raise PolicyError, ~r/invalid rule for Warden.Test.Authz/, fn ->
          Warden.authorize(ctx(admin()), rule)
        end
      end
    end

    test "anonymous actors" do
      assert {:error, %Denial{actor: %Actor{subject: nil}}} =
               Warden.authorize(ctx(nil), authenticated())

      assert Warden.authorize(ctx(nil), public()) == :ok
    end

    test "the first argument must be an actor or a map" do
      assert_raise ArgumentError, fn -> apply(Warden, :authorize, ["admin", role(:admin)]) end
    end
  end

  describe "allowed?/3" do
    test "returns booleans" do
      assert Warden.allowed?(ctx(admin()), role(:admin))
      refute Warden.allowed?(ctx(viewer()), role(:admin))
      assert Warden.allowed?(ctx(admin()), role(:admin), authorizer: OtherAuthz)
    end
  end

  describe "authorize!/3" do
    test "returns :ok or raises ForbiddenError with plug_status 403" do
      assert Warden.authorize!(ctx(admin()), role(:admin)) == :ok

      error =
        assert_raise ForbiddenError, fn -> Warden.authorize!(ctx(viewer()), role(:admin)) end

      assert error.plug_status == 403
      assert Exception.message(error) == "Forbidden"
      assert %Denial{kind: :call} = error.denial
    end

    test "the message names missing roles only with expose_denial_reasons" do
      error =
        assert_raise ForbiddenError, fn ->
          Warden.authorize!(ctx(%{id: "x", roles: []}), role(:admin), authorizer: OtherAuthz)
        end

      assert Exception.message(error) =~ "missing roles: [:admin]"
    end
  end

  describe "filter/4" do
    test "keeps the permitted values, in order" do
      users = Data.users()

      assert Warden.filter(ctx(viewer()), check(:self), users) |> Enum.map(& &1.id) == ["u2"]
      assert Warden.filter(ctx(admin()), role(:admin), users) == users
      assert Warden.filter(ctx(viewer()), role(:admin), users) == []

      actor = Warden.actor(ctx(admin()), authorizer: OtherAuthz)
      assert Warden.filter(actor, role(:admin), [1, 2], authorizer: OtherAuthz) == [1, 2]
    end

    test "validates the rule even for an empty list" do
      assert_raise PolicyError, fn -> Warden.filter(ctx(admin()), role(:ghost), []) end
    end
  end

  describe "authorizer resolution" do
    test "explicit option wins over the default" do
      assert Warden.resolve_authorizer!(OtherAuthz) == OtherAuthz
    end

    test "the actor's own authorizer is used when no option is given" do
      actor = Warden.actor(ctx(admin()), authorizer: OtherAuthz)
      assert Warden.resolve_authorizer!(nil, actor) == OtherAuthz
      # The default (Warden.Test.Authz) would fail this rule's catalog check.
      assert Warden.authorize(actor, role(:admin)) == :ok
    end

    test "the configured default is used last" do
      assert Warden.default_authorizer() == Authz
      assert Warden.resolve_authorizer!(nil, nil) == Authz
    end

    test "an explicit option that differs from the actor's authorizer raises" do
      actor = Warden.actor(ctx(admin()))

      assert_raise PolicyError, ~r/the actor was built by Warden.Test.Authz/, fn ->
        Warden.authorize(actor, role(:admin), authorizer: OtherAuthz)
      end

      assert_raise PolicyError, fn ->
        Warden.allowed?(actor, role(:admin), authorizer: OtherAuthz)
      end
    end

    test "no authorizer anywhere raises an ArgumentError naming the fix" do
      assert_raise ArgumentError, ~r/config :warden, authorizer: MyApp.Authz/, fn ->
        Warden.resolve_authorizer!(nil, nil, nil)
      end
    end

    test "a module that is not an authorizer raises" do
      assert_raise ArgumentError, ~r/must `use Warden.Authorizer`/, fn ->
        Warden.authorize(ctx(admin()), role(:admin), authorizer: Enum)
      end

      assert_raise ArgumentError, ~r/must `use Warden.Authorizer`/, fn ->
        Warden.resolve_authorizer!(nil, nil, Enum)
      end

      assert_raise ArgumentError, ~r/must `use Warden.Authorizer`/, fn ->
        Warden.resolve_authorizer!(nil, nil, Warden.NoSuchModule)
      end
    end
  end

  describe "one authorizer, two front ends" do
    test "GraphQL and the core API reach the same decisions" do
      for user <- [admin(), viewer(), %{id: "u4", roles: []}, nil] do
        graphql = run("{ adminStats }", user).data["adminStats"] != nil
        core = Warden.allowed?(ctx(user), role(:admin))
        assert graphql == core, inspect(user)
      end
    end
  end
end
