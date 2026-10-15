#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
backup=".security-private/defectdojo/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup"
bash scripts/defectdojo-compose.sh exec --interactive=false -T postgres pg_dump -U defectdojo -d defectdojo -Fc > "$backup/database.dump"
bash scripts/defectdojo-compose.sh exec --interactive=false -T uwsgi tar -C /app/media -czf - . > "$backup/media.tar.gz"
cp .security-private/defectdojo/install.env "$backup/install.env"
# Validate the archive structure without restoring over the running database.
bash scripts/defectdojo-compose.sh exec -T postgres pg_restore --list < "$backup/database.dump" > "$backup/database-list.txt"
tar -tzf "$backup/media.tar.gz" > "$backup/media-list.txt"
sha256sum "$backup/database.dump" "$backup/media.tar.gz" "$backup/install.env" > "$backup/SHA256SUMS"
printf 'Respaldo privado verificado: %s (no se imprime su contenido).\n' "$backup"
