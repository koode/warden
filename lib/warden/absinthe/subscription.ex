# Compiled only when the optional `absinthe` dependency is present.
if Code.ensure_loaded?(Absinthe) do
  defmodule Warden.Absinthe.Subscription do
    @moduledoc """
    Warden's subscription publish loop, for the pubsub module of an Absinthe app.

    When Warden denies a subscription's root field at publish time (the object rule of
    the payload, or the field's own rule, for example after a revocation), the subscriber
    gets no push at all for that event. Without this, Absinthe pushes the payload as
    `null`, which still tells the subscriber that the event happened. Partial denials
    inside the payload keep their nulls and redaction, as for queries.

    Absinthe offers no way for a document to cancel its own push, so the app's pubsub
    delegates Absinthe's optional `run_docset/3` callback here. With Absinthe.Phoenix,
    add one line to the endpoint:

        defmodule MyAppWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :my_app
          use Absinthe.Phoenix.Endpoint

          defdelegate run_docset(pubsub, docs, mutation_result), to: Warden.Absinthe.Subscription
        end

    A pubsub that does not delegate keeps Absinthe's own loop; Warden then logs a warning
    once per pubsub module, at the first publish that resolves a subscription field.

    ## Absinthe versions

    `run_docset/3` mirrors the private `run_docset/3` of `Absinthe.Subscription.Local`
    (`lib/absinthe/subscription/local.ex` in Absinthe 1.12), and reuses its public
    `pipeline/2`. It was compared against Absinthe 1.12 only: when the `absinthe`
    requirement admits a later release, compare the two loops again.
    """

    # Subscribe-time checks and `context_id` handling live in
    # `Warden.Absinthe.SubscriptionConfig`.

    require Logger

    alias Absinthe.Phase.Document.Execution.Resolution
    alias Absinthe.Pipeline
    alias Absinthe.Subscription.Local
    alias Warden.Absinthe.Middleware
    alias Warden.Absinthe.Phase.Publish

    @doc """
    Resolves each subscriber's document for a published value and pushes the result,
    except to a subscriber whose subscription root field Warden denied.

    Matches the optional `run_docset/3` callback of `Absinthe.Subscription.Pubsub`:
    delegate to it from the pubsub module. Every other outcome is published as Absinthe's
    own loop does, and an exception while running one document is logged without
    stopping the others.
    """
    @spec run_docset(Absinthe.Subscription.Pubsub.t(), list, term) :: :ok
    def run_docset(pubsub, docs_and_topics, mutation_result) do
      for {topic, key_strategy, doc} <- docs_and_topics do
        run_doc(pubsub, topic, key_strategy, doc, mutation_result)
      end

      :ok
    end

    defp run_doc(pubsub, topic, key_strategy, doc, mutation_result) do
      pipeline = publish_pipeline(doc, mutation_result)
      {:ok, %{result: data} = blueprint, _phases} = Pipeline.run(doc.source, pipeline)

      Logger.debug("""
      Absinthe Subscription Publication
      Field Topic: #{inspect(key_strategy)}
      Subscription id: #{inspect(topic)}
      Data: #{inspect(data)}
      """)

      if not Middleware.root_denied?(blueprint.execution.acc) do
        :ok = pubsub.publish_subscription(topic, data)
      end
    rescue
      exception -> log_pipeline_error(exception, __STACKTRACE__)
    end

    defp publish_pipeline(doc, mutation_result) do
      doc
      |> Local.pipeline(mutation_result)
      |> List.flatten()
      |> Pipeline.insert_before(Resolution, Publish)
    end

    # The log Absinthe writes for a document that raised while publishing.
    defp log_pipeline_error(exception, stacktrace) do
      message = Exception.message(exception)
      formatted = Exception.format_stacktrace(stacktrace)

      Logger.error("""
      #{message}

      #{formatted}
      """)
    end
  end
end
