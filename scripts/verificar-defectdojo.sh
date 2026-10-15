#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
if [[ $# -eq 0 ]]; then set -- check; fi
exec python3 scripts/defectdojo_api.py "$@"
