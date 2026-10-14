#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
test "$(gitleaks version)" = "8.30.0"
hook="$(git rev-parse --git-path hooks/pre-commit)"
source="security/hooks/pre-commit"
bash -n "$source"
if [[ -f "$hook" ]] && ! cmp -s "$source" "$hook"; then
  echo "Existe otro hook: revisar su integración manual antes de reemplazarlo." >&2
  exit 1
fi
install -m 755 "$source" "$hook"
echo "Hook pre-commit TP18 instalado; analiza sólo el índice staged."
