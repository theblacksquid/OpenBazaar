#!/bin/bash


if ! command -v jshint; then
    echo 'ERROR: jshint not installed.'
    exit 1
fi

echo '.: Checking JavaScript source files...'
count=0;
errored=0;
for file in $(find . -name '*.js' -not -name '*.min.js' \
    -not -path './env/*' \
    -not -path './pybitmessage/*' \
    -not -path './html/bower_components/*' \
    -not -path './html/vendors/*'); do
    if ! jshint "$file"; then
        errored=$((errored + 1));
    fi
    count=$((count + 1));
done

if (( errored > 0 )); then
    echo "FAIL: Detected $errored files with errors."
    exit 1
fi
echo "PASS: Successfully checked $count files."
