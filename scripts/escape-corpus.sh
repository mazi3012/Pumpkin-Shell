#!/bin/sh
# Runs the escape corpus (docs/ESCAPE-CORPUS.md) inside real sandboxes and
# prints N/N. Each row's test runs alone with --exact. A test that does not
# exist, or matches more than one test, counts as a failure.
set -u
cd "$(dirname "$0")/.." || exit 2

rows=$(mktemp)
trap 'rm -f "$rows"' EXIT
awk -F'|' '/^\| [A-Z]+-[0-9]+ \|/ {
    id = $2; gsub(/ /, "", id)
    test = $(NF - 1); gsub(/[ `]/, "", test)
    print id, test
}' docs/ESCAPE-CORPUS.md > "$rows"

total=0
passed=0
failed=""
while read -r id test; do
    total=$((total + 1))
    out=$(cargo test --locked -p pks-cli --test sandbox -- --exact "$test" 2>&1)
    if printf '%s\n' "$out" | grep -q "^test result: ok. 1 passed"; then
        passed=$((passed + 1))
        echo "ok    $id $test"
    else
        failed="$failed $id"
        echo "FAIL  $id $test"
    fi
done < "$rows"

echo "$passed/$total passed"
if [ "$passed" -ne "$total" ] || [ "$total" -eq 0 ]; then
    echo "failed:$failed"
    exit 1
fi
