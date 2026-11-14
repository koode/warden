# Compiled only when the optional `phoenix` dependency is present.
if Code.ensure_loaded?(Phoenix.Channel) do
  defmodule Warden.Phoenix.Channel.AllEvents do
    @moduledoc false
    # Phoenix sends a broadcast to the channel process (and so through handle_out/3) only
    # when `event in channel.__intercepts__()`; every other broadcast is encoded once and
    # sent straight to the transport, past the channel and its checks. This set holds
    # every event, so every broadcast reaches handle_out/3. It answers membership only.

    @type t :: %__MODULE__{}

    defstruct []

    defimpl Enumerable do
      def member?(_all_events, _event), do: {:ok, true}
      def count(_all_events), do: {:error, __MODULE__}
      def slice(_all_events), do: {:error, __MODULE__}

      # Listing it would have to stop somewhere and so leave events out; raising makes
      # any code that tries to enumerate it fail loudly instead of skipping the check.
      @spec reduce(Warden.Phoenix.Channel.AllEvents.t(), Enumerable.acc(), Enumerable.reducer()) ::
              no_return()
      def reduce(_all_events, _acc, _fun) do
        raise ArgumentError, "the set of every channel event cannot be listed"
      end
    end
  end
end
