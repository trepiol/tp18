#!/usr/bin/env bash
set -euo pipefail
test "$(gitleaks version)" = "8.30.0"
test -s .gitleaks.toml
test "$(git rev-parse --is-shallow-repository)" = "false"
private=".security-private/gitleaks"
mkdir -p "$private"
chmod 700 "$private"
trap 'rm -f "$private/gitleaks-report.json" "$private/scan.log"' EXIT
if gitleaks git . --config .gitleaks.toml --redact=100 --log-opts=--all \
  --exit-code=10 --no-banner --report-format=json \
  --report-path="$private/gitleaks-report.json" >"$private/scan.log" 2>&1; then
  status=0
else
  status=$?
fi
case "$status" in
  0|10) ;;
  *) echo "Gitleaks: error operativo (código $status)." >&2; exit "$status" ;;
esac
python3 - "$private/gitleaks-report.json" "$status" <<'PY'
import json,sys
findings=json.load(open(sys.argv[1]))
assert isinstance(findings,list)
assert bool(findings)==(int(sys.argv[2])==10)
PY
python3 scripts/security_report.py prepare gitleaks "$private" .security-reports/gitleaks \
  --version 8.30.0 --files gitleaks-report.json
