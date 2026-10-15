#!/usr/bin/env python3
"""Provision TP18 hierarchy and a product-scoped API-only service account.
Run locally after the official Compose initializer completed successfully.
Token values and management command output are never published.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from defectdojo_api import Client, hierarchy, DojoError


def management(code):
    result = subprocess.run([
        'bash', 'scripts/defectdojo-compose.sh', 'exec', '--interactive=false', '-T', 'uwsgi',
        'python', 'manage.py', 'shell', '--no-imports', '-c', code,
    ], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise DojoError('Private management operation failed; no credential printed')
    keys = [line.strip() for line in result.stdout.splitlines() if re.fullmatch(r'[0-9a-f]{40}', line.strip())]
    if len(keys) != 1:
        raise DojoError('Invalid private token response')
    return keys[0]


def main():
    os.chdir(Path(__file__).resolve().parents[1])
    private = Path('.security-private/defectdojo')
    private.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    admin_key = management('from rest_framework.authtoken.models import Token; from django.contrib.auth import get_user_model; print(Token.objects.get_or_create(user=get_user_model().objects.get(username="admin"))[0].key)')
    temporary = private / 'bootstrap-token'
    temporary.write_text(admin_key)
    temporary.chmod(0o600)
    os.environ['DEFECTDOJO_TOKEN_FILE'] = str(temporary)
    try:
        ids = hierarchy(Client(), create=True)
        service_key = management('from rest_framework.authtoken.models import Token; from dojo.models import Dojo_User,Product,Product_Type; u,created=Dojo_User.objects.get_or_create(username="tp18-api-importer",defaults={"is_staff":False,"is_superuser":False,"is_active":True}); assert not u.is_staff and not u.is_superuser and u.is_active; u.set_unusable_password(); u.save(); p=Product.objects.get(name="Notes App"); assert not Product.objects.filter(authorized_users=u).exclude(pk=p.pk).exists(); assert not Product_Type.objects.filter(authorized_users=u).exists(); p.authorized_users.add(u); print(Token.objects.get_or_create(user=u)[0].key)')
        token_file = private / 'api-token'
        token_file.write_text(service_key)
        token_file.chmod(0o600)
        (private / 'context.json').write_text(json.dumps(ids, indent=2)+'\n')
        os.environ['DEFECTDOJO_TOKEN_FILE'] = str(token_file)
        os.environ['DEFECTDOJO_PRODUCT_TYPE_ID'] = str(ids['product_type_id'])
        assert hierarchy(Client(), create=False) == ids
        print('API-only account verified: Notes App membership; no staff, superuser or Product Type membership.')
        print('Observed context:', json.dumps(ids, sort_keys=True))
        print('Private token: .security-private/defectdojo/api-token (mode 600); value omitted.')
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
    except (DojoError, OSError, ValueError, KeyError, AssertionError, subprocess.SubprocessError):
        print('ERROR: provisioning not confirmed; credentials omitted.', file=sys.stderr)
        sys.exit(1)
