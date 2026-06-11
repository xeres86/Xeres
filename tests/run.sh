#!/usr/bin/env bash
# Eight-row boundary table. pass_* must compile (exit 0); fail_* must be rejected (exit 1).
set -u
BIN="${BIN:-./target/release/xeres}"
dir="$(dirname "$0")"
pass=0; fail=0
for f in "$dir"/pass_*.xrs "$dir"/fail_*.xrs; do
  base="$(basename "$f")"
  "$BIN" build "$f" >/dev/null 2>&1
  code=$?
  case "$base" in
    pass_*) want=0 ;;
    fail_*) want=1 ;;
  esac
  if [ "$code" -eq "$want" ]; then
    echo "  ok   $base (exit $code)"; pass=$((pass+1))
  else
    echo "  FAIL $base (got exit $code, wanted $want)"; fail=$((fail+1))
  fi
done
echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
