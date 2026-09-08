#!/usr/bin/env bash
# Regression tests for the security and correctness fixes.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

echo "== frontend render escaping =="
node tests/xss-render.test.js || fail=1

echo
echo "== flow roll-up =="
node tests/rollup.test.js || fail=1

echo
echo "== packet parser =="
BIN=$(mktemp -d)/sniffer_test
if g++ -std=c++17 -O1 -o "$BIN" tests/sniffer_test.cpp -lpcap -lssl -lcrypto -pthread 2>/dev/null; then
  "$BIN" || fail=1
else
  echo "  SKIP  (needs libpcap-dev and libssl-dev)"
fi

echo
if [ "$fail" -ne 0 ]; then echo "TESTS FAILED"; exit 1; fi
echo "ALL TESTS PASSED"
