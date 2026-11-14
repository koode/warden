defmodule Warden.FieldsPropertyTest do
  @moduledoc """
  For random actors and values, the GraphQL output of a `redact_with` object equals
  `Warden.redact/2` on the same struct, field for field, in lists, behind an interface
  and for a single value.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Warden.Test.Fields.{Authz, Comment, UserCard}

  @schema Warden.Test.Fields.Schema
  @tenants ["t1", "t2", nil]
  @users ["abby", "sam", "olivia"]

  @document """
  {
    comments { id body anchor authorId workspaceId seenBody }
    comment { id body anchor authorId }
    cards { id name timezone email }
    nodes { id ... on Comment { body anchor authorId } ... on UserCard { timezone email } }
  }
  """

  defp user do
    gen all(
          id <- member_of(@users),
          kind <- member_of([:user, :agent]),
          staff? <- boolean(),
          first_roles <- tenant_roles(),
          second_roles <- tenant_roles()
        ) do
      roles = if staff?, do: [:staff], else: []
      memberships = %{"t1" => first_roles, "t2" => second_roles}
      %{id: id, kind: kind, roles: roles, memberships: memberships}
    end
  end

  defp tenant_roles, do: list_of(member_of([:owner, :admin, :member, :guest]), max_length: 2)

  defp comment do
    gen all(
          id <- positive_integer(),
          tenant <- member_of(@tenants),
          author <- member_of(@users),
          trashed? <- boolean(),
          hidden? <- frequency([{4, constant(false)}, {1, constant(true)}]),
          body <- string(:alphanumeric, min_length: 1, max_length: 8)
        ) do
      %Comment{
        id: id,
        workspace_id: tenant,
        author_id: author,
        body: body,
        anchor: "anchor-" <> body,
        trashed_at: if(trashed?, do: ~U[2026-11-01 10:00:00Z], else: nil),
        hidden: hidden?
      }
    end
  end

  defp card do
    gen all(
          id <- positive_integer(),
          tenant <- member_of(@tenants),
          name <- string(:alphanumeric, max_length: 6)
        ) do
      %UserCard{
        id: id,
        tenant_id: tenant,
        name: name,
        timezone: "tz-" <> name,
        email: name <> "@x"
      }
    end
  end

  property "GraphQL output of a redact_with object equals Warden.redact/2" do
    check all(
            user <- user(),
            comments <- list_of(comment(), max_length: 6),
            cards <- list_of(card(), max_length: 4),
            max_runs: 150
          ) do
      nodes = Enum.zip_with([comments, cards], fn [comment, card] -> [comment, card] end)
      nodes = List.flatten(nodes)
      context = %{current_user: user, comments: comments, cards: cards, nodes: nodes}

      {:ok, %{data: data} = result} = Absinthe.run(@document, @schema, context: context)
      refute Map.has_key?(result, :errors)

      assert data["comments"] == Enum.map(comments, &expected_comment(&1, context))

      assert data["comment"] ==
               expected_comment(List.first(comments), context, [:seenBody, :workspaceId])

      assert data["cards"] == Enum.map(cards, &expected_card(&1, context))
      assert data["nodes"] == Enum.map(nodes, &expected_node(&1, context))
    end
  end

  defp redacted(value, context), do: Warden.redact(context, value, authorizer: Authz)

  defp expected_comment(comment, context, drop \\ [])
  defp expected_comment(nil, _context, _drop), do: nil
  defp expected_comment(%Comment{hidden: true}, _context, _drop), do: nil

  defp expected_comment(comment, context, drop) do
    redacted = redacted(comment, context)

    %{
      "id" => to_string(redacted.id),
      "body" => redacted.body,
      "anchor" => redacted.anchor,
      "authorId" => redacted.author_id,
      "workspaceId" => redacted.workspace_id,
      "seenBody" => redacted.body
    }
    |> Map.drop(Enum.map(drop, &to_string/1))
  end

  defp expected_card(card, context, keys \\ ["id", "name", "timezone", "email"]) do
    redacted = redacted(card, context)

    %{
      "id" => to_string(redacted.id),
      "name" => redacted.name,
      "timezone" => redacted.timezone,
      "email" => redacted.email
    }
    |> Map.take(keys)
  end

  defp expected_node(%Comment{hidden: true}, _context), do: nil

  defp expected_node(%Comment{} = comment, context) do
    comment
    |> expected_comment(context, [:seenBody, :workspaceId])
  end

  defp expected_node(%UserCard{} = card, context),
    do: expected_card(card, context, ["id", "timezone", "email"])
end
