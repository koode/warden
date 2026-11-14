defmodule Warden.Test.Ecto.Team do
  @moduledoc false
  use Ecto.Schema

  schema "teams" do
    field :workspace_id, :string
    field :name, :string, default: ""
    field :private, :boolean, default: false
    belongs_to(:parent, __MODULE__)
    has_many(:memberships, Warden.Test.Ecto.TeamMembership)
  end
end

defmodule Warden.Test.Ecto.TeamMembership do
  @moduledoc false
  use Ecto.Schema

  schema "team_memberships" do
    field :team_id, :id
    field :user_id, :string
  end
end

defmodule Warden.Test.Ecto.Issue do
  @moduledoc false
  use Ecto.Schema

  schema "issues" do
    field :workspace_id, :string
    field :title, :string, default: ""
    field :state, Ecto.Enum, values: [:open, :closed], default: :open
    field :priority, :decimal
    field :author_id, :string
    field :trashed_at, :utc_datetime
    field :team_name, :string, virtual: true
    belongs_to(:team, Warden.Test.Ecto.Team)
    has_many(:comments, Warden.Test.Ecto.Comment)
  end
end

defmodule Warden.Test.Ecto.Comment do
  @moduledoc false
  use Ecto.Schema

  schema "comments" do
    field :workspace_id, :string
    field :body, :string, default: ""
    field :author_id, :string
    belongs_to(:issue, Warden.Test.Ecto.Issue)
  end
end

defmodule Warden.Test.Ecto.Project do
  @moduledoc false
  use Ecto.Schema

  schema "projects" do
    field :workspace_id, :string
    field :name, :string, default: ""
    field :lead_id, :string
    field :creator_id, :string
    has_many(:project_teams, Warden.Test.Ecto.ProjectTeam)
    many_to_many(:teams, Warden.Test.Ecto.Team, join_through: "project_teams")
  end
end

defmodule Warden.Test.Ecto.ProjectTeam do
  @moduledoc false
  use Ecto.Schema

  schema "project_teams" do
    field :project_id, :id
    field :team_id, :id
  end
end

defmodule Warden.Test.Ecto.ProjectMember do
  @moduledoc false
  use Ecto.Schema

  schema "project_members" do
    field :project_id, :id
    field :user_id, :string
  end
end

defmodule Warden.Test.Ecto.Share do
  @moduledoc false
  use Ecto.Schema

  schema "shares" do
    field :issue_id, :id
    field :grantee_id, :string
    field :expires_at, :naive_datetime
  end
end

defmodule Warden.Test.Ecto.Summary do
  @moduledoc false
  use Ecto.Schema

  schema "summaries" do
    field :workspace_id, :string
    field :subject_type, :string
    field :subject_id, :id
  end
end

defmodule Warden.Test.Ecto.OauthClient do
  @moduledoc false
  use Ecto.Schema

  schema "oauth_clients" do
    field :workspace_id, :string
    field :name, :string, default: ""
    field :owner_id, :string
  end
end

defmodule Warden.Test.Ecto.Note do
  @moduledoc false
  use Ecto.Schema

  schema "notes" do
    field :workspace_id, :string
    field :author_id, :string
    field :secret, :boolean, default: false
  end
end
