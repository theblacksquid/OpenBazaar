#!/bin/bash

echo '.: Checking for newlines at EOFs...'
count=0;
errored=0;
for file in $(find . -not -path './env/*' -not -path './pybitmessage/*' \
    -and '(' -name '*.html' -o -name '*.js' ')' -not -name '*.min.js' \
    | grep -v bower_components); do
    if [ "$(tail -c1 "$file")" != '' ]; then
        echo "$file: No new line at end of file"
        errored=$((errored + 1));
    fi
    count=$((count + 1));
done

if (( errored > 0 )); then
    echo "FAIL: Detected $errored files with errors."
    exit 1
fi
echo "PASS: Successfully checked $count files."
