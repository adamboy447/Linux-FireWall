#!/bin/bash
# Offline policy checks (no kernel, no agent):
#   policies/*.yaml          must validate
#   policies/invalid/*.yaml  must be rejected with the code in their "# expect:" line
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INV=${MYFW_INVENTORY:-$ROOT/lab/inventory.yaml}
FWCTL=${FWCTL:-fwctl}
fail=0

for p in "$ROOT"/policies/*.yaml; do
	if out=$($FWCTL validate "$p" --inventory "$INV" --json); then
		echo "ok    valid     $(basename "$p")"
	else
		echo "FAIL  invalid   $(basename "$p")"; echo "$out"; fail=1
	fi
done

for p in "$ROOT"/policies/invalid/*.yaml; do
	want=$(sed -n 's/^# expect: *//p' "$p" | head -1)
	if out=$($FWCTL validate "$p" --inventory "$INV" --json); then
		echo "FAIL  accepted  $(basename "$p") (expected $want)"; fail=1; continue
	fi
	if WANT="$want" python3 -c '
import json, os, sys
r, want = json.load(sys.stdin), os.environ["WANT"]
codes = {f["code"] for f in r.get("findings") or []}
ok = want in codes or (want == "schema" and "schema" in (r.get("message") or ""))
sys.exit(0 if ok else 1)' <<<"$out"; then
		echo "ok    rejected  $(basename "$p") ($want)"
	else
		echo "FAIL  rejected  $(basename "$p") but not with $want"; echo "$out"; fail=1
	fi
done
exit $fail
