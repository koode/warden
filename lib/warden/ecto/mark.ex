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
    # The struct must still be the one loaded: same
    # prefix and same values in every persisted field (the tenant included), so a changed
    # struct is decided as it is.
    #
    # Postgres and MySQL do not use `__meta__.context`; a struct whose context is already
    # set (by another adapter) is never marked.

    alias Warden.Actor
    alias Warden.Ecto.Info

    @enforce_keys [:policy, :action, :actor, :delegator, :context, :prefix, :fields]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            policy: module,
            action: atom,
            actor: reference,
            delegator: reference | nil,
            context: map,
            prefix: String.t() | nil,
            fields: map
          }

    # Marks the structs of the policy's schema in `rows`, when `query` returned its root
    # binding as is and the actor has an instance. `context` is the one the scope ran
    # with. A struct from a join, a `select_merge` or a source other than the schema's own
    # is never marked.
    @spec mark_all(list, map, atom, Actor.t(), map, Ecto.Query.t()) :: list
    def mark_all(rows, info, action, %Actor{instance: instance} = actor, context, query)
        when is_reference(instance) do
      if root_select?(query.select),
        do: Enum.map(rows, &mark(&1, info, action, actor, context)),
        else: rows
    end

    def mark_all(rows, _info, _action, _actor, _context, _query), do: rows

    defp root_select?(nil), do: true
    defp root_select?(%Ecto.Query.SelectExpr{expr: {:&, _meta, [0]}}), do: true
    defp root_select?(_select), do: false

    defp mark(
           %schema{__meta__: %Ecto.Schema.Metadata{context: nil} = meta} = struct,
           info,
           action,
           actor,
           context
         )
         when schema == info.schema do
      if meta.source == schema.__schema__(:source) do
        mark = %__MODULE__{
          policy: info.policy,
          action: action,
          actor: actor.instance,
          delegator: actor.delegator && actor.delegator.instance,
          context: comparable(context),
          prefix: meta.prefix,
          fields: persisted(struct)
        }

        Ecto.put_meta(struct, context: mark)
      else
        struct
      end
    end

    defp mark(row, _info, _action, _actor, _context), do: row

    # True when `struct` carries a mark of `info`'s policy for `action`, this actor
    # instance (one side of a delegated actor included) and this decision's `context`,
    # and is still the struct that was loaded.
    @spec admits?(term, map, atom, Actor.t(), map) :: boolean
    def admits?(
          %{__meta__: %Ecto.Schema.Metadata{context: %__MODULE__{} = mark}} = struct,
          info,
          action,
          %Actor{instance: instance},
          context
        )
        when is_reference(instance) do
      mark.policy == info.policy and mark.action == action and
        instance in [mark.actor, mark.delegator] and mark.context === comparable(context) and
        mark.prefix == Info.prefix(struct) and mark.fields == persisted(struct)
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

    defp persisted(%schema{} = struct), do: Map.take(struct, schema.__schema__(:fields))
  end

  defimpl Inspect, for: Warden.Ecto.Mark do
    # A mark holds the row's values, the actor's instance and the context: show none.
    def inspect(mark, _opts),
      do: "#Warden.Ecto.Mark<#{inspect(mark.policy)} #{inspect(mark.action)}>"
  end
end
