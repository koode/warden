defmodule Warden.Phoenix.ChannelCompileTest do
  use ExUnit.Case, async: true

  alias Warden.Phoenix.Channel
  alias Warden.Rule

  defp compile_channel(options, body \\ "def join(_topic, _params, socket), do: {:ok, socket}") do
    name = "Warden.Test.Compiled.Channel#{System.unique_integer([:positive])}"

    Code.compile_string("""
    defmodule #{name} do
      use Phoenix.Channel
      import Warden.Rule
      use Warden.Phoenix.Channel, #{options}

      #{body}
    end
    """)
  end

  describe "compile-time validation" do
    test "a valid channel compiles" do
      assert [{_module, _binary}] =
               compile_channel(
                 "rule: role(:member), value: &String.length/1, authorizer: Warden.Test.ChannelAuthz"
               )
    end

    test "an unknown role fails compilation" do
      assert_raise ArgumentError, ~r/invalid Warden.Phoenix.Channel rule .*ghost/, fn ->
        compile_channel("rule: role(:ghost), authorizer: Warden.Test.ChannelAuthz")
      end
    end

    test "an undeclared check fails compilation" do
      assert_raise ArgumentError, ~r/invalid Warden.Phoenix.Channel rule/, fn ->
        compile_channel("rule: check(:nope), authorizer: Warden.Test.ChannelAuthz")
      end
    end

    test "the rule is required" do
      assert_raise ArgumentError, ~r/needs a `rule:`/, fn ->
        compile_channel("authorizer: Warden.Test.ChannelAuthz")
      end
    end

    test "an unknown option fails compilation" do
      assert_raise ArgumentError, ~r/unknown Warden.Phoenix.Channel options: \[:rechek\]/, fn ->
        compile_channel("rule: public(), rechek: []")
      end
    end

    test "recheck takes :every_push and one positive {:every, ms}" do
      assert_raise ArgumentError, ~r/positive integer ms/, fn ->
        compile_channel("rule: public(), recheck: [{:every, 0}]")
      end

      assert_raise ArgumentError, ~r/positive integer ms/, fn ->
        compile_channel("rule: public(), recheck: :always")
      end

      assert_raise ArgumentError, ~r/one \{:every, ms\}/, fn ->
        compile_channel("rule: public(), recheck: [{:every, 10}, {:every, 20}]")
      end
    end

    test "value must be a function of arity 1 or 2" do
      assert_raise ArgumentError, ~r/`value:` must be nil or a function/, fn ->
        compile_channel(
          "rule: public(), value: fn topic, params, extra -> {topic, params, extra} end"
        )
      end

      assert_raise ArgumentError, ~r/`value:` must be nil or a function/, fn ->
        compile_channel(~s[rule: public(), value: "workspace"])
      end

      assert [{_module, _binary}] =
               compile_channel(
                 "rule: public(), value: fn topic when is_binary(topic) -> topic end"
               )

      assert [{_module, _binary}] = compile_channel("rule: public(), value: &{&1, &2}")
    end

    test "on_deny must name an existing function of arity 2" do
      assert_raise ArgumentError, ~r/does not exist/, fn ->
        compile_channel("rule: public(), on_deny: {String, :nope}")
      end

      assert_raise ArgumentError, ~r/must be \{module, function\}/, fn ->
        compile_channel("rule: public(), on_deny: :deny")
      end
    end

    test "use Phoenix.Channel must come first" do
      assert_raise ArgumentError,
                   ~r/`use Phoenix.Channel` before `use Warden.Phoenix.Channel`/,
                   fn ->
                     Code.compile_string("""
                     defmodule Warden.Test.Compiled.Unordered#{System.unique_integer([:positive])} do
                       import Warden.Rule
                       use Warden.Phoenix.Channel, rule: public()
                       use Phoenix.Channel

                       def join(_topic, _params, socket), do: {:ok, socket}
                     end
                     """)
                   end
    end

    test "a channel without join/3 fails compilation" do
      assert_raise ArgumentError, ~r/defines no join\/3/, fn ->
        compile_channel("rule: public()", "")
      end
    end
  end

  describe "socket_context/1" do
    defmodule BadContextAuthz do
      @moduledoc false
      use Warden.Authorizer, roles: [:member]

      @impl true
      def subject(context), do: context[:current_user]

      @impl true
      def roles(_user, _context), do: [:member]

      @impl true
      def socket_context(_socket), do: :not_a_map
    end

    test "a context that is not a map raises Warden.PolicyError" do
      socket = %Phoenix.Socket{assigns: %{current_user: %{id: "u1"}}}

      assert_raise Warden.PolicyError, ~r/socket_context\/1 must return a map/, fn ->
        Channel.authorize(socket, Rule.public(), authorizer: BadContextAuthz)
      end
    end
  end
end
