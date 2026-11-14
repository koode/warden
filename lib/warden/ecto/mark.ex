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
    # The struct must still be the one loaded: same prefix and same values in every
    # persisted field (the tenant included), so a changed struct is decided as it is.
    #
    # Postgres and MySQL do not use `__meta__.context`; a struct whose context is already
    # set (by another adapter) is never marked.

    alias Warden.Actor
    alias Warden.Ecto.Info

    @enforce_keys [:policy, :action, :actor, :delegator, :prefix, :fields]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            policy: module,
            action: atom,
            actor: reference,
            delegator: reference | nil,
            prefix: String.t() | nil,
            fields: map
          }

    # Marks the structs of the policy's schema in `rows`, when `query` returned its root
    # binding as is and the actor has an instance. A struct from a join, a `select_merge`
    # or a source other than the schema's own is never marked.
    @spec mark_all(list, map, atom, Actor.t(), Ecto.Query.t()) :: list
    def mark_all(rows, info, action, %Actor{instance: instance} = actor, query)
        when is_reference(instance) do
      if root_select?(query.select),
        do: Enum.map(rows, &mark(&1, info, action, actor)),
        else: rows
    end

    def mark_all(rows, _info, _action, _actor, _query), do: rows

    defp root_select?(nil), do: true
    defp root_select?(%Ecto.Query.SelectExpr{expr: {:&, _meta, [0]}}), do: true
    defp root_select?(_select), do: false

    defp mark(
           %schema{__meta__: %Ecto.Schema.Metadata{context: nil} = meta} = struct,
           info,
           action,
           actor
         )
         when schema == info.schema do
      if meta.source == schema.__schema__(:source) do
        mark = %__MODULE__{
          policy: info.policy,
          action: action,
          actor: actor.instance,
          delegator: actor.delegator && actor.delegator.instance,
          prefix: meta.prefix,
          fields: persisted(struct)
        }

        Ecto.put_meta(struct, context: mark)
      else
        struct
      end
    end

    defp mark(row, _info, _action, _actor), do: row

    # True when `struct` carries a mark of `info`'s policy for `action` and this actor
    # instance (one side of a delegated actor included), and is still the struct that was
    # loaded.
    @spec admits?(term, map, atom, Actor.t()) :: boolean
    def admits?(
          %{__meta__: %Ecto.Schema.Metadata{context: %__MODULE__{} = mark}} = struct,
          info,
          action,
          %Actor{instance: instance}
        )
        when is_reference(instance) do
      mark.policy == info.policy and mark.action == action and
        instance in [mark.actor, mark.delegator] and mark.prefix == Info.prefix(struct) and
        mark.fields == persisted(struct)
    end

    def admits?(_struct, _info, _action, _actor), do: false

    # The struct without a mark, for code that must decide it through the policy itself.
    @spec unmark(term) :: term
    def unmark(%{__meta__: %Ecto.Schema.Metadata{context: %__MODULE__{}}} = struct),
      do: Ecto.put_meta(struct, context: nil)

    def unmark(row), do: row

    defp persisted(%schema{} = struct), do: Map.take(struct, schema.__schema__(:fields))
  end

  defimpl Inspect, for: Warden.Ecto.Mark do
    # A mark holds the row's values and the actor's instance: show neither.
    def inspect(mark, _opts),
      do: "#Warden.Ecto.Mark<#{inspect(mark.policy)} #{inspect(mark.action)}>"
  end
end
