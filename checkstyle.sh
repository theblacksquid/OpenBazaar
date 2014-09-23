#!/bin/bash
set -o errexit
set -o pipefail

ERR=false

if $ERR ; then
    exit 1
else
    exit 0
fi
