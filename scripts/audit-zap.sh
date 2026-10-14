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
chmod 770 "$private"
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
preflight_path=log_path.parent/"preflight.log"
try:
    startup_checks=json.loads(preflight_path.read_text())
except (OSError,ValueError):
    startup_checks=None
diagnostic={
    "startup_checks":startup_checks,
    "tool":"zap", "sha":os.environ.get("GITHUB_SHA"),
    "run_id":os.environ.get("GITHUB_RUN_ID"),
    "exit_code":int(sys.argv[1]), "elapsed_seconds":int(sys.argv[2]),
    "phase":sys.argv[4],
    "timeout":int(sys.argv[1])==124,
    "plan_succeeded":"Automation plan succeeded!" in log,
    "raw_report_exists":(log_path.parent/"zap-report.json").is_file(),
    "jobs":{
        name:{"started":log.count("Job "+name+" started"),
              "finished":log.count("Job "+name+" finished")}
        for name in ("requestor","spider","passiveScan-wait","activeScan","report")
    },
    "log_indicators":{
        "errors":log.count("ERROR"), "warnings":log.count("WARN"),
        "dns_errors":log.count("UnknownHostException"),
        "permission_errors":log.count("Permission denied"),
        "memory_errors":log.count("OutOfMemoryError"),
    },
    "scanner_user":"zap (UID 1000)",
    "raw_logs_published":False,
}
Path(".security-reports/diagnostics/zap.json").write_text(json.dumps(diagnostic,indent=2)+"\n")
PY
  timeout --kill-after=3 10 docker logs --tail 100 "$backend" >"$private/backend.log" 2>&1 || :
  timeout --kill-after=3 10 docker logs --tail 100 "$db" >"$private/postgres.log" 2>&1 || :
  timeout --kill-after=3 15 docker rm -f "$scanner" "$backend" "$db" >/dev/null 2>&1 || :
  timeout --kill-after=3 15 docker network rm "$network" >/dev/null 2>&1 || :
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
  --memory 256m --user "1000:$(id -g)" -v "$private:/zap/wrk/reports" \
  --entrypoint python3 "$zap_image" -c \
  'import json,os,urllib.request; d=json.load(urllib.request.urlopen("http://backend:5000/health",timeout=10)); checks={p:os.access(p,os.W_OK) for p in ("/zap","/home/zap","/zap/wrk/reports")}; print(json.dumps({"backend_connected":d["db"]=="connected","uid":os.getuid(),"writable":checks})); assert d["db"]=="connected" and all(checks.values())' \
  >"$private/preflight.log" 2>&1
echo "ZAP: backend accesible desde la imagen del escáner; iniciando Automation Framework."
# Inspect native container state instead of waiting on the attached Docker client.
phase=automation
docker run --detach --name "$scanner" --network "$network" \
  --add-host "backend:$backend_ip" --memory 3g --cpus 2 \
  --user "1000:$(id -g)" -e JAVA_TOOL_OPTIONS=-Duser.home=/zap/wrk/reports \
  -v "$PWD/security/zap/zap.yaml:/zap/wrk/plan.yaml:ro" \
  -v "$private:/zap/wrk/reports" "$zap_image" \
  bash -c 'umask 0007; exec zap.sh -Xmx1536m -dir /zap/wrk/reports/.zap -cmd -silent -port 8091 -autorun /zap/wrk/plan.yaml' >/dev/null
deadline=$((SECONDS + 720))
status=124
while (( SECONDS < deadline )); do
  snapshot="$(timeout --kill-after=3 15 docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$scanner")"
  read -r container_state container_exit <<< "$snapshot"
  if [[ "$container_state" == exited || "$container_state" == dead ]]; then
    status="$container_exit"
    break
  fi
  sleep 3
done
timeout --kill-after=3 15 docker logs "$scanner" >"$private/scan.log" 2>&1
plan_succeeded="$(python3 - "$private/scan.log" <<'PY'
import sys
from pathlib import Path
print(int("Automation plan succeeded!" in Path(sys.argv[1]).read_text(errors="replace")))
PY
)"
# A completed plan can have a genuine report even if process shutdown fails.
# Preserve that evidence, native exit status and deployment block separately.
if [[ "$status" == 0 || "$plan_succeeded" == 1 ]]; then
  phase=report-validation
  export TP18_ZAP_PROCESS_EXIT_CODE="$status"
  python3 scripts/security_report.py prepare zap "$private" .security-reports/zap \
    --version 2.17.0 --files zap-report.json
fi
if [[ "$status" != 0 ]]; then
  phase=process-exit
  echo "ZAP: error operativo del proceso (código $status); el job conserva su fallo." >&2
  exit "$status"
fi
phase=completed
echo "ZAP: Automation Framework y proceso finalizados correctamente."
