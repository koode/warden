defmodule Warden.Test.Repo do
  @moduledoc false
  use Ecto.Repo, otp_app: :warden, adapter: Ecto.Adapters.Postgres
end

defmodule Warden.Test.Database do
  @moduledoc false
  # Creates the database of the `:postgres` suite, its tables and the repo, and drops the
  # database when the suite ends. Only databases whose name starts with `warden_test` are
  # ever created or dropped.

  alias Ecto.Adapters.{Postgres, SQL}
  alias Warden.Test.Repo

  @default_url "postgres://localhost/warden_test"
  @prefix "warden_test"

  @tables [
    """
    CREATE TABLE teams (
      id bigserial PRIMARY KEY,
      workspace_id text,
      name text NOT NULL DEFAULT '',
      private boolean NOT NULL DEFAULT false,
      parent_id bigint
    )
    """,
    """
    CREATE TABLE team_memberships (
      id bigserial PRIMARY KEY,
      team_id bigint NOT NULL,
      user_id text NOT NULL
    )
    """,
    """
    CREATE TABLE issues (
      id bigserial PRIMARY KEY,
      workspace_id text,
      team_id bigint,
      title text NOT NULL DEFAULT '',
      state text NOT NULL DEFAULT 'open',
      priority numeric,
      author_id text,
      trashed_at timestamp(0)
    )
    """,
    """
    CREATE TABLE comments (
      id bigserial PRIMARY KEY,
      workspace_id text,
      issue_id bigint,
      body text NOT NULL DEFAULT '',
      author_id text
    )
    """,
    """
    CREATE TABLE projects (
      id bigserial PRIMARY KEY,
      workspace_id text,
      name text NOT NULL DEFAULT '',
      lead_id text,
      creator_id text
    )
    """,
    """
    CREATE TABLE project_teams (
      id bigserial PRIMARY KEY,
      project_id bigint NOT NULL,
      team_id bigint NOT NULL
    )
    """,
    """
    CREATE TABLE project_members (
      id bigserial PRIMARY KEY,
      project_id bigint NOT NULL,
      user_id text NOT NULL
    )
    """,
    """
    CREATE TABLE shares (
      id bigserial PRIMARY KEY,
      issue_id bigint NOT NULL,
      grantee_id text NOT NULL,
      expires_at timestamp(0)
    )
    """,
    """
    CREATE TABLE summaries (
      id bigserial PRIMARY KEY,
      workspace_id text,
      subject_type text NOT NULL,
      subject_id bigint NOT NULL
    )
    """,
    """
    CREATE TABLE oauth_clients (
      id bigserial PRIMARY KEY,
      workspace_id text,
      name text NOT NULL DEFAULT '',
      owner_id text
    )
    """,
    """
    CREATE TABLE notes (
      id bigserial PRIMARY KEY,
      workspace_id text,
      author_id text,
      secret boolean NOT NULL DEFAULT false
    )
    """
  ]

  @spec tables() :: [String.t()]
  def tables do
    ~w(teams team_memberships issues comments projects project_teams project_members shares) ++
      ~w(summaries oauth_clients notes)
  end

  def setup! do
    config = config()
    _down = Postgres.storage_down(config)
    :ok = Postgres.storage_up(config)
    Application.put_env(:warden, Repo, config)
    {:ok, _pid} = Repo.start_link()

    Enum.each(@tables, &({:ok, _result} = SQL.query(Repo, &1, [])))

    SQL.Sandbox.mode(Repo, :manual)
  end

  def teardown! do
    config = config()
    if Process.whereis(Repo), do: Repo.stop()

    :ok = Postgres.storage_down(config)
  end

  defp config do
    url = System.get_env("WARDEN_DATABASE_URL", @default_url)
    config = Ecto.Repo.Supervisor.parse_url(url)
    database = Keyword.fetch!(config, :database)

    if not String.starts_with?(database, @prefix) do
      raise ArgumentError,
            "the :postgres suite only uses databases named #{@prefix}*, got: #{database}"
    end

    Keyword.merge(config, pool: Ecto.Adapters.SQL.Sandbox, pool_size: 10, log: false)
  end
end
