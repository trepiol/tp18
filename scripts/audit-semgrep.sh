#!/usr/bin/env bash
set -euo pipefail
private=".security-private/semgrep"
mkdir -p "$private" .semgrep-tmp
chmod 700 "$private"
helm template tp15 devops-tp12/chart -f devops-tp12/values-local.yaml \
  > .semgrep-tmp/helm-rendered.yaml
semgrep scan --config=auto --config=p/owasp-top-ten --config=p/python \
  --config=p/dockerfile --config=p/terraform --config=p/kubernetes \
  --json --output="$private/semgrep-results.json" \
  devops-tp12/app devops-tp12/monitoring-k8s-manifests.yaml guia-11 .semgrep-tmp \
  >"$private/scan.log" 2>&1
python3 scripts/security_report.py prepare semgrep "$private" .security-reports/semgrep \
  --version "$(semgrep --version 2>/dev/null)" --files semgrep-results.json
