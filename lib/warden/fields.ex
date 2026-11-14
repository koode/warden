defmodule Warden.Fields do
  @moduledoc """
  A field policy: which fields of a struct an actor may read, declared once and applied
  everywhere the struct leaves the application (GraphQL, REST, webhooks, chat posts,
  exports, prompts).

      defmodule MyApp.Authz.CommentFields do
        use Warden.Fields, authorizer: MyApp.Authz, for: MyApp.Comment

        redact :body, with: "", unless: check(:live)
        redact :anchor, with: nil, unless: check(:live)
      end

      defmodule MyApp.Authz.UserCardFields do
        use Warden.Fields, authorizer: MyApp.Authz, for: MyApp.UserCard

        redact :timezone, with: nil, unless: tenant_role(:member)
      end

  The authorizer lists its field policies (`fields: [MyApp.Authz.CommentFields, ...]`),
  and every front end applies them:

      Warden.redact(actor, comment)                 # the struct, denied fields replaced
      Warden.redact(actor, comments)                # a list, batched per rule
      Warden.redact(actor, payload, deep: true)     # nested registered structs too
      Warden.visible_fields(actor, comment)         # MapSet of the fields left as they are

      object :comment do
        authorize can(MyApp.Authz.Comments, :read)
        redact_with MyApp.Authz.CommentFields
      end

  ## `redact field, with: value, unless: rule`

    * `field` - a field of the `for:` struct. Any other atom fails compilation, and so
      does a field named twice.
    * `with:` (required) - the value the field gets when the rule denies. A literal (or
      any compile-time term).
    * `unless:` (required) - a Warden rule over the struct: checks get the struct as
      `Warden.Check.value`, `tenant_role/1` reads the struct's tenant. The field keeps its
      value only when the rule passes. The rule is validated against the authorizer's
      catalog at compile time; `covered()` and rules that read field arguments
      (`tenant_role(role, tenant: {:arg, path})`, `can(policy, action, arg: path)`) fail
      compilation, because a redaction rule is about the struct alone.

  The rule builders of `Warden.Rule` are imported.

  ## Options of `use Warden.Fields`

    * `:authorizer` (required) - the authorizer whose `fields:` lists this module. Checked
      at compile time.
    * `:for` (required) - the struct module the policy redacts.

  ## Semantics

    * Only a passing rule keeps a field. A system actor passes no check that does not name
      its kind, no role and no tenant role, so a webhook or a job sees the redacted value
      unless a rule says what its kind sees (`any_of([check(:live), kind(:webhook)])`).
    * A delegated actor keeps a field only when both actors pass its rule.
    * Redaction returns new structs. It never writes anything, and nothing Warden builds
      while redacting (checks, telemetry, errors) shows the redacted values.
  """

  alias Warden.Decision
  alias Warden.Fields.Redactor

  @option_keys [:authorizer, :for]
  @redact_keys [:unless, :with]

  defmacro __using__(opts) do
    env = __CALLER__
    {opts, _binding} = Code.eval_quoted(opts, [], env)

    info =
      case validate_options(opts, env.module) do
        {:ok, info} ->
          info

        {:error, errors} ->
          messages = Enum.map_join(errors, "\n", &("  * " <> &1))

          compile_error!(
            env,
            "invalid Warden.Fields options in #{inspect(env.module)}:\n#{messages}"
          )
      end

    # Read by `redact/2` while the module body is expanded.
    Module.put_attribute(env.module, :__warden_fields_info__, info)
    Module.register_attribute(env.module, :__warden_redactions__, accumulate: true)

    quote do
      import Warden.Rule,
        only: [
          public: 0,
          authenticated: 0,
          deny: 0,
          role: 1,
          any_role: 1,
          permission: 1,
          all_permissions: 1,
          any_permission: 1,
          check: 1,
          check: 2,
          all_of: 1,
          any_of: 1,
          covered: 0,
          tenant_role: 1,
          tenant_role: 2,
          kind: 1,
          credential_scope: 1,
          session: 0,
          can: 2,
          can: 3
        ]

      import Warden.Fields, only: [redact: 2]

      @before_compile Warden.Fields
    end
  end

  @doc """
  Declares that `field` gets the value `with:` unless the actor passes the rule
  `unless:`. See the module documentation.
  """
  defmacro redact(field, opts) do
    env = __CALLER__
    info = Module.get_attribute(env.module, :__warden_fields_info__)

    if info == nil do
      compile_error!(env, "`redact` must be used in a module that does `use Warden.Fields`")
    end

    field = eval!(field, env)
    opts = eval!(opts, env)
    entry = redaction!(field, opts, info, env)
    taken = env.module |> Module.get_attribute(:__warden_redactions__) |> Enum.map(& &1.field)

    if field in taken do
      compile_error!(env, "`redact` names #{inspect(field)} twice; declare each field once")
    end

    Module.put_attribute(env.module, :__warden_redactions__, entry)
    :ok
  end

  @doc false
  defmacro __before_compile__(env) do
    base = Module.get_attribute(env.module, :__warden_fields_info__)
    redactions = env.module |> Module.get_attribute(:__warden_redactions__) |> Enum.reverse()
    info = Map.put(base, :redactions, redactions)

    quote do
      # The entry point Warden calls (see Warden.Fields.Redactor). It must be public, and
      # is hidden from the user's docs.
      # credo:disable-for-lines:3 ExSlop.Check.Readability.DocFalseOnPublicFunction
      @doc false
      def __warden_fields__(:info), do: unquote(Macro.escape(info))
    end
  end

  @doc """
  Returns the field policy registered for a struct (or a struct module) in
  `authorizer`'s `fields:`, or `nil`. Raises `Warden.PolicyError` when two field policies
  of the authorizer are for the same struct.
  """
  @spec fields_for(module, struct | module) :: module | nil
  def fields_for(authorizer, %module{}), do: fields_for(authorizer, module)

  def fields_for(authorizer, module) when is_atom(module) do
    authorizer
    |> Redactor.registry()
    |> Map.get(module)
  end

  def fields_for(_authorizer, _value), do: nil

  defp redaction!(field, opts, info, env) do
    if not (is_atom(field) and field != nil) do
      compile_error!(env, "`redact` needs a field name (an atom), got: #{inspect(field)}")
    end

    if field not in info.struct_fields do
      compile_error!(env, """
      `redact` names #{inspect(field)}, which is not a field of #{inspect(info.for)} \
      (fields: #{inspect(info.struct_fields)})\
      """)
    end

    if not Keyword.keyword?(opts) or Enum.sort(Keyword.keys(opts)) != @redact_keys do
      compile_error!(env, "`redact #{inspect(field)}` takes exactly `with:` and `unless:`")
    end

    rule = Keyword.fetch!(opts, :unless)

    case rule_errors(rule, info.authorizer) do
      [] ->
        %{field: field, with: Keyword.fetch!(opts, :with), rule: rule}

      errors ->
        problems = Enum.join(errors, "; ")
        compile_error!(env, "invalid `unless:` rule for #{inspect(field)}: #{problems}")
    end
  end

  # The catalog errors of the core API (which refuse `covered()`), plus rules that read
  # field arguments: a redaction is decided from the struct alone, the same in every front
  # end, so a client-chosen argument must never widen it.
  defp rule_errors(rule, authorizer) do
    errors = Decision.rule_errors(rule, authorizer)

    if errors == [] and reads_args?(rule),
      do: ["a redaction rule is about the struct; it cannot read field arguments (`arg:`)"],
      else: errors
  end

  defp reads_args?({:tenant_role, _role, opts}) when is_list(opts),
    do: match?({:arg, _path}, Keyword.get(opts, :tenant))

  defp reads_args?({:can, _policy, _action, opts}) when is_list(opts),
    do: Keyword.has_key?(opts, :arg)

  defp reads_args?({tag, rules}) when tag in [:all, :any] and is_list(rules),
    do: Enum.any?(rules, &reads_args?/1)

  defp reads_args?(_rule), do: false

  defp validate_options(opts, module) when is_list(opts) do
    authorizer = Keyword.get(opts, :authorizer)
    for_module = Keyword.get(opts, :for)

    errors =
      unknown_option_errors(opts) ++
        authorizer_errors(authorizer, module) ++ for_errors(for_module)

    if errors == [] do
      struct_fields = for_module.__struct__() |> Map.keys() |> List.delete(:__struct__)
      info = %{authorizer: authorizer, for: for_module, struct_fields: Enum.sort(struct_fields)}
      {:ok, info}
    else
      {:error, errors}
    end
  end

  defp validate_options(_opts, _module), do: {:error, ["options must be a keyword list"]}

  defp unknown_option_errors(opts) do
    case Keyword.keys(opts) -- @option_keys do
      [] -> []
      unknown -> ["unknown options: #{inspect(unknown)}"]
    end
  end

  # The field policy depends on its authorizer at compile time, never the other way
  # round: the authorizer only names its field policies.
  defp authorizer_errors(authorizer, module) when is_atom(authorizer) and authorizer != nil do
    if authorizer?(authorizer) do
      listed = Map.get(authorizer.__warden_catalog__(), :fields, [])

      if module in listed,
        do: [],
        else: ["#{inspect(authorizer)} does not list #{inspect(module)} in its `fields:`"]
    else
      ["`:authorizer` #{inspect(authorizer)} does not `use Warden.Authorizer`"]
    end
  end

  defp authorizer_errors(_authorizer, _module), do: ["`:authorizer` (a module) is required"]

  defp authorizer?(authorizer) do
    match?({:module, _module}, Code.ensure_compiled(authorizer)) and
      function_exported?(authorizer, :__warden_catalog__, 0)
  end

  defp for_errors(for_module) when is_atom(for_module) and for_module != nil do
    if match?({:module, _module}, Code.ensure_compiled(for_module)) and
         function_exported?(for_module, :__struct__, 0),
       do: [],
       else: ["`:for` #{inspect(for_module)} is not a struct module"]
  end

  defp for_errors(_for_module), do: ["`:for` (the struct module) is required"]

  defp eval!(ast, env) do
    {value, _binding} = Code.eval_quoted(ast, [], env)
    value
  rescue
    error ->
      message = Exception.message(error)

      compile_error!(
        env,
        "could not evaluate the arguments of `redact` at compile time: #{message}"
      )
  end

  @spec compile_error!(Macro.Env.t(), String.t()) :: no_return()
  defp compile_error!(env, message) do
    raise CompileError, file: env.file, line: env.line, description: message
  end
end
