#!/usr/bin/env bash
set -euo pipefail
image="$(python3 -c 'import json; print(json.load(open("security/tools.json"))["threagile_image"])')"
private="$PWD/.security-private/threagile"
mkdir -p "$private"
chmod 700 "$private"
docker run --rm --network none --memory 2g -e HOME=/out -e XDG_CACHE_HOME=/out/.cache --user "$(id -u):$(id -g)" \
  -v "$PWD/devops-tp12/threagile.yaml:/model.yaml:ro" \
  -v "$private:/out" "$image" -model /model.yaml -output /out \
  >"$private/scan.log" 2>&1
python3 scripts/security_report.py prepare threagile "$private" .security-reports/threagile \
  --version 1.0.0 --files risks.json report.pdf data-flow-diagram.png data-asset-diagram.png
