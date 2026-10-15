#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
private_env="${TP18_DOJO_ENV:-$repo/.security-private/defectdojo/install.env}"
if [[ ! -f "$private_env" ]]; then
  echo 'ERROR: falta el entorno privado de DefectDojo.' >&2
  exit 1
fi
exec docker compose --env-file "$private_env" -f "$repo/infra/defectdojo/compose.yml" "$@"
