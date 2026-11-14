defmodule Warden.ActorContextTest do
  use ExUnit.Case, async: true

  import Warden.Rule
  import Warden.Test.V2.People

  alias Warden.Test.V2.Authz

  test "checks get the context an actor was built from" do
    actor = actor(abby(), %{plain: true})
    assert Warden.allowed?(actor, check(:plain))
    assert Warden.filter(actor, check(:plain), [1, 2]) == [1, 2]
    assert Warden.explain(actor, check(:plain)).result == :ok
  end

  test "a context: option wins over the actor's own" do
    actor = actor(abby(), %{plain: true})
    refute Warden.allowed?(actor, check(:plain), context: %{plain: false})
  end

  test "a delegated actor uses the request's context in both passes" do
    delegated =
      Warden.on_behalf_of(actor(olivia(), %{plain: true}), actor(sam(), %{plain: false}))

    assert Warden.allowed?(delegated, check(:plain))
  end

  test "a system actor has no context of its own" do
    webhook = Warden.system_actor(Authz, kind: :webhook)
    assert webhook.context == nil
    assert Warden.allowed?(webhook, check(:hooked))
  end

  test "inspect never shows the context" do
    actor = actor(abby(), %{plain: true, session_token: "token-crimson"})
    refute inspect(actor) =~ "token-crimson"
  end
end
