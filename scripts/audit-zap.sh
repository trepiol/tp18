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
mkdir -p "$private" .security-reports/diagnostics
chmod 700 "$private"
rm -f "$private/scan.log" "$private/zap-report.json" .security-reports/zap/manifest.json
started_at=$SECONDS
phase=setup
cleanup() {
  status=$?
  python3 - "$status" "$((SECONDS - started_at))" "$private/scan.log" "$phase" <<'PY'
import json,os,sys
from pathlib import Path
log_path=Path(sys.argv[3])
log=log_path.read_text(errors="replace") if log_path.exists() else ""
diagnostic={
    "tool":"zap", "sha":os.environ.get("GITHUB_SHA"),
    "run_id":os.environ.get("GITHUB_RUN_ID"),
    "exit_code":int(sys.argv[1]), "elapsed_seconds":int(sys.argv[2]),
    "phase":sys.argv[4],
    "timeout":int(sys.argv[1])==124,
    "log_indicators":{
        "errors":log.count("ERROR"), "warnings":log.count("WARN"),
        "dns_errors":log.count("UnknownHostException"),
        "permission_errors":log.count("Permission denied"),
        "memory_errors":log.count("OutOfMemoryError"),
    },
    "raw_logs_published":False,
}
Path(".security-reports/diagnostics/zap.json").write_text(json.dumps(diagnostic,indent=2)+"\n")
PY
  docker logs "$backend" >"$private/backend.log" 2>&1 || :
  docker logs "$db" >"$private/postgres.log" 2>&1 || :
  docker rm -f "$scanner" "$backend" "$db" >/dev/null 2>&1 || :
  docker network rm "$network" >/dev/null 2>&1 || :
}
trap cleanup EXIT
docker network create --internal "$network" >/dev/null
db_password="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
docker run -d --name "$db" --network "$network" --network-alias db \
  --memory 1g --tmpfs /var/lib/postgresql/data:rw,size=512m \
  -e POSTGRES_DB=notesdb -e POSTGRES_USER=notes \
  -e POSTGRES_PASSWORD="$db_password" "$pg_image" >/dev/null
docker run -d --name "$backend" --network "$network" --network-alias backend \
  --memory 1g -e DB_HOST=db -e DB_NAME=notesdb -e DB_USER=notes \
  -e DB_PASSWORD="$db_password" "$image" >/dev/null
unset db_password
phase=backend-readiness
ready=false
for attempt in {1..90}; do
  if timeout 10 docker exec "$backend" python3 -c \
    'import json,urllib.request; d=json.load(urllib.request.urlopen("http://127.0.0.1:5000/health",timeout=5)); assert d["db"]=="connected"' \
    >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != "true" ]]; then
  echo "ZAP: backend sin readiness con PostgreSQL; revisar logs privados." >&2
  exit 1
fi
phase=network-preflight
backend_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$backend")"
python3 - "$backend_ip" <<'PY'
import ipaddress,sys
assert ipaddress.ip_address(sys.argv[1]).is_private
PY
# Bypass DNS search-path differences on the hosted runner.
timeout 30 docker run --rm --network "$network" --add-host "backend:$backend_ip" \
  --memory 256m --entrypoint python3 "$zap_image" -c \
  'import json,urllib.request; d=json.load(urllib.request.urlopen("http://backend:5000/health",timeout=10)); assert d["db"]=="connected"' \
  >"$private/preflight.log" 2>&1
echo "ZAP: backend accesible desde la imagen del escáner; iniciando Automation Framework."
# Keep Java's home writable for arbitrary runner UID and bound process runtime.
phase=automation
if timeout 720 docker run --rm --name "$scanner" --network "$network" \
  --add-host "backend:$backend_ip" --memory 3g --cpus 2 \
  --user "$(id -u):$(id -g)" -e JAVA_TOOL_OPTIONS=-Duser.home=/zap/wrk/reports \
  -v "$PWD/security/zap/zap.yaml:/zap/wrk/plan.yaml:ro" \
  -v "$private:/zap/wrk/reports" "$zap_image" \
  zap.sh -Xmx1536m -dir /zap/wrk/reports/.zap -cmd -silent -port 8091 \
  -autorun /zap/wrk/plan.yaml >"$private/scan.log" 2>&1; then
  echo "ZAP: Automation Framework finalizado."
else
  status=$?
  echo "ZAP: fallo operativo del proceso (código $status); diagnóstico seguro disponible." >&2
  exit "$status"
fi
phase=report-validation
python3 scripts/security_report.py prepare zap "$private" .security-reports/zap \
  --version 2.17.0 --files zap-report.json
phase=completed
