#!/bin/bash

echo '.: Checking for non-executable files with execute bit set...'
errored=0;
for file in $(find . -perm -111 \
    -not -path "./env/*" \
    -not -path './node_modules' -and '(' \
    -name 'LICENSE' \
    -name 'README' \
    -o -name '*.cpp' \
    -o -name '*.css' \
    -o -name '*.eot' \
    -o -name '*.html' \
    -o -name '*.js' \
    -o -name '*.json' \
    -o -name '*.less' \
    -o -name '*.map' \
    -o -name '*.md' \
    -o -name '*.png' \
    -o -name '*.scss' \
    -o -name '*.svg' \
    -o -name '*.txt' \
    -o -name '*.ttf' \
    -o -name '*.woff' \
    -o -name '*.yml' ')' ); do
    echo "$file: Execute bit set; please remove."
    errored=$((errored + 1));
done

if (( errored > 0 )); then
    echo "FAIL: Detected $errored files with errors."
    exit 1
fi
echo 'PASS: No suspicious execute flag detected.'
