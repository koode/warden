[
  # The `rx_admin_feed_raise` subscription config raises on purpose: the red-team test
  # checks that Warden refuses the subscription before the user's config ever runs.
  {"test/support/redteam_exec_support.ex", :no_return}
]
