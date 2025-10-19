# TODO: Test compiled output variations against baselines.
#       Test against actual schema directories. Test can do a git clone or include a copy. At least these:
#       - 1.6.0 (latest released)
#       - 1.0.0-rc.2 (oldest)
#       - splunk extension (for use with 1.0.0-rc.2)
#       Baseline variations:
#       - 1.6.0 with and without platform extensions
#       - 1.0.0-rc.2 (without dev extensions that fails)
#       - 1.0.0-rc.2 with splunk extension
#       - Each of these in current layout, current layout browser mode, and legacy mode

# TODO: Test uses of compiled schemas.
#       - Test latest know working schema browser with browser mode compiled schemas.
#       - Test event validation in browser with compiled schemas. Make sure no "browser mode" stuff is used.
#       - (Future) Test event validation with future open source validation library (libraries). Without browser mode.
#         This could be Python library, Go library, Java library, and/or all 3.
#       - (Future) Test event enrichment with future open source python enrichment library. Without browser mode.
#         This could be Python library, Go library, Java library, and/or all 3.
