import Config

# The default authorizer for every Warden entry point that is not given `authorizer:`.
config :warden, authorizer: Warden.Test.Authz
