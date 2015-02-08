#!/bin/bash

if ! command -v bandit; then
    echo 'ERROR: bandit not installed.'
    exit 1
fi

echo '.: Checking python source files using bandit...'
bandit -a vuln -c bandit.yaml db/*.py db/migrations/*.py node/*.py rudp/*.py tests/*.py

# Since bandit is used for informative purposes only, its exit status
# should not matter for the build.
exit 0
