#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
command -v docker >/dev/null
command -v python3 >/dev/null
docker compose version
available=$(df -Pk . | awk 'NR == 2 {print $4}')
if (( available < 8 * 1024 * 1024 )); then
  echo 'ERROR: se requieren al menos 8 GiB libres antes de instalar. Ampliar almacenamiento; no se borra ningún volumen.' >&2
  exit 1
fi
python3 - <<'PYTHON'
import secrets
from pathlib import Path
p=Path('.security-private/defectdojo')
p.mkdir(parents=True, exist_ok=True)
p.chmod(0o700)
f=p/'install.env'
if f.exists():
    raise SystemExit('ERROR: el entorno privado ya existe; no se sobrescribe.')
pw=secrets.token_hex(24)
values={'DD_DATABASE_PASSWORD':pw,
        'DD_DATABASE_URL':f'postgresql://defectdojo:{pw}@postgres:5432/defectdojo',
        'DD_SECRET_KEY':secrets.token_hex(32),
        'DD_CREDENTIAL_AES_256_KEY':secrets.token_hex(16),
        'DD_ADMIN_PASSWORD':secrets.token_urlsafe(30)}
f.write_text(''.join(k+'='+v+'\n' for k,v in values.items()))
f.chmod(0o600)
print('Entorno privado creado con permisos 600; credenciales omitidas.')
PYTHON
bash scripts/defectdojo-compose.sh config --quiet
bash scripts/defectdojo-compose.sh pull
bash scripts/defectdojo-compose.sh up -d --no-build
bash scripts/defectdojo-compose.sh ps -a
