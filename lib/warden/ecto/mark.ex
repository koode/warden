# Compiled only when the optional `ecto` dependency is present.
if Code.ensure_loaded?(Ecto) do
  defmodule Warden.Ecto.Mark do
    @moduledoc false
    # What `Warden.Ecto.all/5` leaves in `__meta__.context` of every root struct its scope
    # admitted, so a later decision about that struct (a `can/2` object rule,
    # `Warden.Ecto.filter/4`) does not ask the database again.
    #
    # A mark admits a struct only for the policy and action it was scoped for and for the
    # actor instance that loaded it (`Warden.Actor` `instance`): a rebuilt actor, another
    # request or a delegation is a new instance. For a delegated actor it also names the
    # instance of the delegator that actor carries, since its scope was the AND of both.
    # It also holds the context the scope ran with, and admits only a decision under an
    # identical (`===`) context: a policy may read the context, so a scope run under one
    # context says nothing about another. The one key left out of that comparison is
    # `:loader`, where Absinthe's Dataloader plugin keeps the request's data-loading cache
    # and replaces it on every resolution pass; it holds data, not the actor's authority.
    #
    # The struct must still be the one loaded, as far as the decision can tell: same
    # prefix and same values in every field the policy's decision can read (the policy's
    # `mark_fields`: the primary key, the tenant and the fields its clauses read, or every
    # persisted field for a policy with a hand-written `scope/4`, `allowed?/4` or `when:`
    # function). A change to such a field drops the mark; a change to any other field
    # keeps it, since the scope's answer does not depend on it.
    #
    # Everything but those values is the same for every row of one call, so it lives in
    # one `Warden.Ecto.Mark.Call` that every row's mark references: a call over many rows
    # holds that term once, and each row adds a small tuple of values.
    #
    # Postgres and MySQL do not use `__meta__.context`; a struct whose context is already
    # set (by another adapter) is never marked.

    alias Warden.Actor
    alias Warden.Ecto.Info

    defmodule Call do
      @moduledoc false
      # What one `Warden.Ecto.all/5` call shares between the marks of its rows.
      @enforce_keys [:policy, :action, :actor, :delegator, :context, :prefix]
      defstruct @enforce_keys

      @type t :: %__MODULE__{
              policy: module,
              action: atom,
              actor: reference,
              delegator: reference | nil,
              context: map,
              prefix: String.t() | nil
            }
    end

    @enforce_keys [:call, :values]
    defstruct @enforce_keys

    @type t :: %__MODULE__{call: Call.t(), values: tuple}

    # Marks the structs of the policy's schema in `rows`, when `query` returned its root
    # binding as is and the actor has an instance. `context` is the one the scope ran
    # with. A struct from a join, a `select_merge` or a source other than the schema's own
    # is never marked, and neither is a struct from another prefix than the call's (the
    # prefix of the first struct of the schema).
    @spec mark_all(list, map, atom, Actor.t(), map, Ecto.Query.t()) :: list
    def mark_all(rows, info, action, %Actor{instance: instance} = actor, context, query)
        when is_reference(instance) do
      with true <- root_select?(query.select),
           %{__meta__: %Ecto.Schema.Metadata{prefix: prefix}} <- first_of(rows, info.schema) do
        call = %Call{
          policy: info.policy,
          action: action,
          actor: instance,
          delegator: actor.delegator && actor.delegator.instance,
          context: comparable(context),
          prefix: prefix
        }

        fields = fields(info)
        source = info.schema.__schema__(:source)
        Enum.map(rows, &mark(&1, info.schema, source, call, fields))
      else
        _unmarked -> rows
      end
    end

    def mark_all(rows, _info, _action, _actor, _context, _query), do: rows

    defp root_select?(nil), do: true
    defp root_select?(%Ecto.Query.SelectExpr{expr: {:&, _meta, [0]}}), do: true
    defp root_select?(_select), do: false

    defp first_of(rows, schema), do: Enum.find(rows, &match?(%{__struct__: ^schema}, &1))

    defp mark(
           %schema{__meta__: %Ecto.Schema.Metadata{context: nil, source: source, prefix: prefix}} =
             struct,
           schema,
           source,
           %Call{prefix: prefix} = call,
           fields
         ) do
      mark = %__MODULE__{call: call, values: values(struct, fields)}
      %{struct | __meta__: %{struct.__meta__ | context: mark}}
    end

    defp mark(row, _schema, _source, _call, _fields), do: row

    # True when `struct` carries a mark of `info`'s policy for `action`, this actor
    # instance (one side of a delegated actor included) and this decision's `context`,
    # and is still the struct that was loaded, in every field the decision can read.
    @spec admits?(term, map, atom, Actor.t(), map) :: boolean
    def admits?(
          %{__meta__: %Ecto.Schema.Metadata{context: %__MODULE__{call: %Call{} = call} = mark}} =
            struct,
          info,
          action,
          %Actor{instance: instance},
          context
        )
        when is_reference(instance) do
      call.policy == info.policy and call.action == action and
        instance in [call.actor, call.delegator] and call.context === comparable(context) and
        call.prefix == Info.prefix(struct) and mark.values === values(struct, fields(info))
    end

    def admits?(_struct, _info, _action, _actor, _context), do: false

    # The context without `:loader` (see the module comment).
    defp comparable(context) when is_map(context), do: Map.delete(context, :loader)
    defp comparable(context), do: context

    # The struct without a mark, for code that must decide it through the policy itself.
    @spec unmark(term) :: term
    def unmark(%{__meta__: %Ecto.Schema.Metadata{context: %__MODULE__{}}} = struct),
      do: Ecto.put_meta(struct, context: nil)

    def unmark(row), do: row

    defp fields(%{mark_fields: :all, schema: schema}), do: schema.__schema__(:fields)
    defp fields(%{mark_fields: fields}), do: fields

    defp values(struct, fields) do
      values = for field <- fields, do: Map.fetch!(struct, field)
      List.to_tuple(values)
    end
  end

  defimpl Inspect, for: Warden.Ecto.Mark do
    # A mark holds the row's values, the actor's instance and the context: show none.
    def inspect(%{call: call}, _opts),
      do: "#Warden.Ecto.Mark<#{inspect(call.policy)} #{inspect(call.action)}>"
  end

  defimpl Inspect, for: Warden.Ecto.Mark.Call do
    def inspect(call, _opts),
      do: "#Warden.Ecto.Mark.Call<#{inspect(call.policy)} #{inspect(call.action)}>"
  end
end
