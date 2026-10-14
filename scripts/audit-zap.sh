#!/usr/bin/env bash
set -euo pipefail
image="${IMAGE_NAME:-tp16-notes-backend}:${IMAGE_TAG:-$(git rev-parse HEAD)}"
zap_image="$(python3 -c 'import json; print(json.load(open("security/tools.json"))["zap_image"])')"
pg_image="$(python3 -c 'import json; print(json.load(open("security/tools.json"))["postgres_image"])')"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
network="tp18-dast-$suffix"
db="tp18-db-$suffix"
backend="tp18-backend-$suffix"
scanner="tp18-zap-$suffix"
private="$PWD/.security-private/zap"
mkdir -p "$private"
chmod 700 "$private"
cleanup() {
  docker logs "$backend" >"$private/backend.log" 2>&1 || :
  docker logs "$db" >"$private/postgres.log" 2>&1 || :
  docker rm -f "$scanner" "$backend" "$db" >/dev/null 2>&1 || :
  docker network rm "$network" >/dev/null 2>&1 || :
}
trap cleanup EXIT
# No host port is published. The ephemeral network has no external routing.
docker network create --internal "$network" >/dev/null
db_password="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
docker run -d --name "$db" --network "$network" --network-alias db \
  --memory 1g --tmpfs /var/lib/postgresql/data:rw,size=512m -e POSTGRES_DB=notesdb -e POSTGRES_USER=notes \
  -e POSTGRES_PASSWORD="$db_password" "$pg_image" >/dev/null
docker run -d --name "$backend" --network "$network" --network-alias backend \
  --memory 1g -e DB_HOST=db -e DB_NAME=notesdb -e DB_USER=notes \
  -e DB_PASSWORD="$db_password" "$image" >/dev/null
unset db_password
ready=false
for attempt in {1..90}; do
  if timeout 10 docker exec "$backend" python3 -c \
    'import json,urllib.request; d=json.load(urllib.request.urlopen("http://127.0.0.1:5000/health", timeout=5)); assert d["db"]=="connected"' \
    >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != "true" ]]; then
  echo "ZAP: el backend no alcanzó readiness con PostgreSQL; revisar logs privados." >&2
  exit 1
fi
# Runs as the current UID so no world-writable report directory is needed.
docker run --rm --name "$scanner" --network "$network" --memory 3g --cpus 2 --user "$(id -u):$(id -g)" \
  -v "$PWD/security/zap/zap.yaml:/zap/wrk/plan.yaml:ro" \
  -v "$private:/zap/wrk/reports" "$zap_image" \
  zap.sh -Xmx1536m -dir /zap/wrk/reports/.zap -cmd -port 8091 -autorun /zap/wrk/plan.yaml >"$private/scan.log" 2>&1
python3 scripts/security_report.py prepare zap "$private" .security-reports/zap \
  --version pinned-image --files zap-report.json
