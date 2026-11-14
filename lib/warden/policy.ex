defmodule Warden.Policy do
  @moduledoc """
  One declaration per resource and action: may this actor do `action` on this value?

      defmodule MyApp.Authz.Docs do
        use Warden.Policy,
          authorizer: MyApp.Authz,
          for: MyApp.Doc,
          actions: [:read, :write],
          tenant: :workspace_id

        @impl true
        def allowed?(:read, actor, %MyApp.Doc{} = doc, _context),
          do: doc.public? or doc.author_id == actor.subject.id

        def allowed?(:write, actor, %MyApp.Doc{} = doc, _context),
          do: doc.author_id == actor.subject.id

        # `can(MyApp.Authz.Docs, :write, arg: [:id])` passes `{MyApp.Doc, id}`.
        def allowed?(action, actor, {MyApp.Doc, id}, context),
          do: allowed?(action, actor, MyApp.Docs.get!(id), context)
      end

  The authorizer lists its policies (`policies: [MyApp.Authz.Docs]`), and rules use them
  with `can/2,3`:

      import Warden.Rule
      Warden.authorize(actor, can(MyApp.Authz.Docs, :read), value: doc)
      Warden.filter(actor, can(MyApp.Authz.Docs, :read), docs)   # one allowed_many/4 call

      object :doc do
        authorize can(MyApp.Authz.Docs, :read)                    # object rule, batched over lists
      end

      field :update_doc, :doc do
        arg :id, non_null(:id)
        authorize can(MyApp.Authz.Docs, :write, arg: [:id])       # before the resolver
      end

  ## Options

    * `:authorizer` (required) - the authorizer whose `policies:` lists this module.
    * `:for` (required) - the struct module the policy is about.
    * `:actions` (required) - the actions it decides. A rule naming another action fails
      compilation.
    * `:tenant` - the field of the struct that holds its tenant. It is the default of
      `c:Warden.Authorizer.tenant_of/1` for this struct.
    * `:system_kinds` - the system actor kinds the policy is asked about. Every other
      system actor is denied without calling it. Default `[]`.

  ## Callbacks

  `c:allowed?/4` returns `true`, `false` or `{:deny, reason}`; only `true` allows.
  `c:allowed_many/4`, when defined, answers a whole list at once (`Warden.filter/4`, GraphQL
  lists) and must return one result per value, in order. A wrong length, a bad result or
  a raise is a `Warden.PolicyError` and allows nothing.

  ## What Warden decides before calling the policy

    * A `nil` value is denied.
    * A system actor whose kind is not in `system_kinds:` is denied.
    * When the actor's credential is bound to a tenant, a value of another tenant (or of
      no known tenant, such as `{schema, id}` from `arg:`) is denied.
    * A delegated actor is asked about twice, once for itself and once for its delegator,
      and both must allow.
  """

  alias Warden.Actor
  alias Warden.Policy.Dispatch

  @typedoc "What a policy returns for one value. Only `true` allows."
  @type result :: boolean | {:deny, Warden.Denial.reason()}

  @doc """
  Decides whether `actor` may do `action` on `value`. `value` is a struct of the policy's
  `for:` module, or `{module, id}` for `can(policy, action, arg: path)`.
  """
  @callback allowed?(action :: atom, Actor.t(), value :: term, context :: map) :: result

  @doc "Decides `action` for many values at once: one result per value, in order."
  @callback allowed_many(action :: atom, Actor.t(), values :: [term], context :: map) :: [result]

  @optional_callbacks allowed_many: 4

  @option_keys [:authorizer, :for, :actions, :tenant, :system_kinds]

  defmacro __using__(opts) do
    {opts, _binding} = Code.eval_quoted(opts, [], __CALLER__)

    info =
      case validate_options(opts, __CALLER__.module) do
        {:ok, info} ->
          info

        {:error, errors} ->
          raise CompileError,
            file: __CALLER__.file,
            line: __CALLER__.line,
            description:
              "invalid Warden.Policy options in #{inspect(__CALLER__.module)}:\n" <>
                Enum.map_join(errors, "\n", &("  * " <> &1))
      end

    quote do
      @behaviour Warden.Policy
      @before_compile Warden.Policy

      # The entry points Warden calls (see Warden.Policy.Dispatch). They must be public,
      # and are hidden from the user's docs.
      # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
      @doc false
      def __warden_policy__(:info), do: unquote(Macro.escape(info))

      # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
      @doc false
      def __warden_decide__(action, actor, values, context),
        do: unquote(Dispatch).callbacks_decide(__MODULE__, action, actor, values, context)

      defoverridable __warden_decide__: 4
    end
  end

  @doc false
  defmacro __before_compile__(env) do
    if not Module.defines?(env.module, {:allowed?, 4}) do
      raise CompileError,
        file: env.file,
        line: env.line,
        description: "#{inspect(env.module)} uses Warden.Policy but does not define allowed?/4"
    end

    :ok
  end

  @doc """
  Returns the policy registered for a struct (or a struct module) in `authorizer`'s
  `policies:`, or `nil`.

  Raises `Warden.PolicyError` when `policies:` lists two policies for the same struct:
  which one decides (and which `tenant:` field the binding reads) must not depend on
  their order. The registry is built once per compiled authorizer and kept in
  `:persistent_term`, so a lookup costs a map access.
  """
  @spec policy_for(module, struct | module) :: module | nil
  def policy_for(authorizer, %module{}), do: policy_for(authorizer, module)

  def policy_for(authorizer, module) when is_atom(module) do
    case registry(authorizer) do
      {:ok, registry} -> Map.get(registry, module)
      {:error, message} -> raise Warden.PolicyError, message
    end
  end

  def policy_for(_authorizer, _value), do: nil

  # The struct => policy map of an authorizer, cached per compiled version of it.
  defp registry(authorizer) do
    key = {__MODULE__, :registry, authorizer, authorizer.module_info(:md5)}

    case :persistent_term.get(key, nil) do
      nil ->
        registry = build_registry(authorizer)
        :persistent_term.put(key, registry)
        registry

      registry ->
        registry
    end
  end

  defp build_registry(authorizer) do
    authorizer.__warden_catalog__()
    |> Map.get(:policies, [])
    |> Enum.reduce_while({:ok, %{}}, fn policy, {:ok, registry} ->
      struct_module = Dispatch.info!(policy).for

      case Map.fetch(registry, struct_module) do
        {:ok, first} ->
          {:halt, {:error, duplicate_message(authorizer, struct_module, first, policy)}}

        :error ->
          {:cont, {:ok, Map.put(registry, struct_module, policy)}}
      end
    end)
  end

  defp duplicate_message(authorizer, struct_module, first, second) do
    """
    #{inspect(authorizer)} lists two policies for #{inspect(struct_module)}: \
    #{inspect(first)} and #{inspect(second)}; list one policy per struct\
    """
  end

  # Shared with `Warden.Ecto.Policy`, which validates the same core options.
  # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
  @doc false
  @spec validate_options(term, module) :: {:ok, map} | {:error, [String.t()]}
  def validate_options(opts, module) when is_list(opts) do
    authorizer = Keyword.get(opts, :authorizer)
    for_module = Keyword.get(opts, :for)
    actions = Keyword.get(opts, :actions)
    tenant = Keyword.get(opts, :tenant)
    system_kinds = Keyword.get(opts, :system_kinds, [])

    errors =
      unknown_option_errors(opts) ++
        authorizer_errors(authorizer, module) ++
        for_errors(for_module) ++
        actions_errors(actions) ++
        tenant_errors(tenant) ++
        system_kinds_errors(system_kinds, authorizer)

    if errors == [] do
      info = %{
        authorizer: authorizer,
        for: for_module,
        actions: actions,
        tenant: tenant,
        system_kinds: system_kinds,
        enforces_binding: false
      }

      {:ok, info}
    else
      {:error, errors}
    end
  end

  def validate_options(_opts, _module), do: {:error, ["options must be a keyword list"]}

  defp unknown_option_errors(opts) do
    case Keyword.keys(opts) -- @option_keys do
      [] -> []
      unknown -> ["unknown options: #{inspect(unknown)}"]
    end
  end

  # The policy depends on its authorizer at compile time, never the other way round:
  # the authorizer only names its policies.
  defp authorizer_errors(authorizer, module) when is_atom(authorizer) and authorizer != nil do
    if authorizer?(authorizer) do
      policies = Map.get(authorizer.__warden_catalog__(), :policies, [])

      if module in policies,
        do: [],
        else: ["#{inspect(authorizer)} does not list #{inspect(module)} in its `policies:`"]
    else
      ["`:authorizer` #{inspect(authorizer)} does not `use Warden.Authorizer`"]
    end
  end

  defp authorizer_errors(_authorizer, _module), do: ["`:authorizer` (a module) is required"]

  defp authorizer?(authorizer) do
    match?({:module, _module}, Code.ensure_compiled(authorizer)) and
      function_exported?(authorizer, :__warden_catalog__, 0)
  end

  defp for_errors(for_module) when is_atom(for_module) and for_module != nil, do: []
  defp for_errors(_for_module), do: ["`:for` (the struct module) is required"]

  defp actions_errors([_ | _] = actions) do
    cond do
      not Enum.all?(actions, &(is_atom(&1) and not is_nil(&1))) ->
        ["`:actions` must be a list of atoms, got: #{inspect(actions)}"]

      Enum.uniq(actions) != actions ->
        ["`:actions` contains duplicates: #{inspect(actions -- Enum.uniq(actions))}"]

      true ->
        []
    end
  end

  defp actions_errors(_actions), do: ["`:actions` must be a non-empty list of atoms"]

  defp tenant_errors(tenant) when is_atom(tenant), do: []
  defp tenant_errors(_tenant), do: ["`:tenant` must be a field name (an atom)"]

  defp system_kinds_errors(kinds, authorizer) when is_list(kinds) do
    declared =
      if is_atom(authorizer) and authorizer != nil and authorizer?(authorizer),
        do: MapSet.to_list(authorizer.__warden_catalog__().kinds),
        else: []

    for kind <- kinds, kind == :user or kind not in declared do
      "`:system_kinds` names #{inspect(kind)}, which is not a declared kind other than :user"
    end
  end

  defp system_kinds_errors(_kinds, _authorizer), do: ["`:system_kinds` must be a list of kinds"]
end
