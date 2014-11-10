#!/bin/bash

PYTHON="./env/bin/python"
if [ ! -x $PYTHON ]; then
  echo "No python executable found at ${PYTHON}"
  if type python2 &>/dev/null; then
    PYTHON=python2
  elif type python &>/dev/null; then
    PYTHON=python
  else
    echo "No python executable found anywhere"
    exit
  fi
fi

# Execute from root dir as: bash upgrade_db.sh [--path <db_path>]
if [ -z "$1" ]; then
    $PYTHON -m db.migrations.migration1 upgrade
    $PYTHON -m db.migrations.migration2 upgrade
    $PYTHON -m db.migrations.migration3 upgrade
else
    $PYTHON -m db.migrations.migration1 upgrade --path $1
    $PYTHON -m db.migrations.migration2 upgrade --path $1
    $PYTHON -m db.migrations.migration3 upgrade --path $1
fi
