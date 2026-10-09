import Config

# The library itself configures nothing. The test suite sets a default authorizer.
if config_env() == :test do
  import_config "test.exs"
end
