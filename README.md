# TP18 — Preparación para OWASP DefectDojo

Repositorio independiente basado en **TP17 `7072a9b`**, con historial completo.
Aplicación objetivo: Notes App de `devops-tp12`. **DefectDojo aún no está
instalado ni integrado.** Esta entrega prepara sus entradas y validaciones.

## Arquitectura y fases

1. **Build & Package:** tests de TP12 y un único build del backend. Tarball
   Docker identificado por SHA del commit y verificado mediante SHA-256.
2. **Security Audits:** ZAP, Threagile, Semgrep, Trivy y Gitleaks generan
   reportes nuevos para el mismo SHA en una ejecución de `cicd.yml`.
3. **Vulnerability Management, preparada:** recopilación de los artifacts
   del run actual, formatos, SHA, hashes y reportes ausentes. Sin importaciones
   simuladas ni conexiones a DefectDojo.
4. **Release & Deploy:** publicación y Helm heredados, sólo desde `main` con
   los controles y la recopilación exitosos. Se conservan las comprobaciones
   de credenciales, contexto Kubernetes y PostgreSQL.

ZAP y Trivy cargan el **mismo tarball**, sin reconstruir el backend.
Gitleaks, Semgrep y Threagile son independientes del build y de fallos de
Trivy. ZAP requiere build exitoso. El lint histórico TP06 permanece independiente.

## Herramientas, formatos y artifacts

| Herramienta | Reporte / parser DefectDojo | Política | Artifact |
|---|---|---|---|
| ZAP 2.17.0 | JSON tradicional + XML / **ZAP Scan** | Findings informativos; fallos operativos bloquean | `tp18-zap-<SHA>` |
| Threagile 1.0.0 | `risks.json` / **Threagile risks report**; PDF y diagramas | Riesgos informativos; errores bloquean | `tp18-threagile-<SHA>` |
| Semgrep 1.177.0 | `semgrep-results.json` / **Semgrep JSON Report**; SARIF | Guard OWASP ERROR heredado bloqueante | `tp18-semgrep-<SHA>` |
| Trivy 0.74.0 | SCA, secretos, imagen e IaC JSON / **Trivy Scan** | HIGH/CRITICAL bloquean; LOW/MEDIUM informativos | `tp18-trivy-high-<SHA>`, `tp18-trivy-low-<SHA>` |
| Gitleaks 8.30.0 | `gitleaks-report.json` / **Gitleaks Scan** | Andon bloqueante; auditoría informativa | `tp18-gitleaks-<SHA>` |

Los seis bundles de reportes tienen retención de **14 días**. Cada uno incluye
`manifest.json` con herramienta, versión, SHA, run, conteos, warnings y hashes.
El índice es `tp18-collection-<SHA>`.
ZAP publica además un diagnóstico operativo con código, duración y contadores
seguros de errores; no sustituye el reporte ni incluye logs crudos. El artifact de imagen heredado
`tp16-backend-image-<SHA>` mantiene retención de un día.

Los JSON Trivy conservan findings, severidades e identidad de la imagen;
se retiran snippets, mensajes interpolados y configuración cruda de imagen
(variables, labels e historial de build) que podrían exponer valores sensibles.

### Compatibilidad real de parsers

El parser oficial **ZAP Scan exige XML**, no JSON. Se conserva el JSON
solicitado y se genera XML equivalente sanitizado para importarlo con ese
parser. El HTML es un resumen generado desde datos sanitizados.

El reporte TP17 de Gitleaks omitía `Description`, necesario para reconocer
el formato actual. La transformación incorpora una descripción determinista
por regla/commit/rango. `Secret`, `Match` y `Message` quedan `REDACTED`; no se
publican autores, emails, texto del commit ni fragmentos de código. El
fingerprint conserva trazabilidad por ubicación; no se usa un secreto real
para deduplicar. Una versión futura de Dojo debe confirmar esa deduplicación.

Los parsers se contrastan con el código oficial fijado en
`security/tools.json`. El harness ejecuta sus lectores con modelos mínimos;
**no prueba Django, ORM, API ni import/reimport en una instancia instalada**.

## Jobs y comportamiento ante fallos

`cicd.yml` orquesta tests, build, los dos jobs Trivy, los dos Gitleaks,
`semgrep`, `zap-audit`, `threat-modeling`,
`collect-security-reports` y `deploy-k8s-helm`.
`semgrep.yml` es reutilizable mediante `workflow_call` y también admite
ejecución manual; se eliminan sus triggers duplicados de push/PR.
`pr-check.yml` se conserva como antecedente.

- **Andon rojo:** la auditoría y la recopilación siguen sus condiciones
  `always()`; recopilar evidencia no convierte el gate en exitoso.
- **Build fallido/omitido:** Gitleaks, Semgrep y Threagile siguen. Trivy y ZAP
  se omiten; el colector informa sus bundles ausentes y devuelve error.
- **Escáner con error:** no se inventa JSON vacío ni manifest exitoso.
- **Cero hallazgos:** hay un reporte real validado y su manifest.
- **Deploy:** exige main y éxito de build, los cuatro jobs Trivy/Gitleaks,
  Semgrep, ZAP, Threagile y recopilación.

Semgrep conserva las cinco configuraciones explícitas y `auto`. JSON y SARIF
derivan del mismo análisis; el guard OWASP ERROR conserva su alcance original,
incluidos los templates Helm. Los avisos no fatales `PartialParsing` se
registran con ruta y conteo; los demás errores impiden publicar un bundle
válido. Un warning no implica cobertura completa del archivo afectado.
La carga SARIF sigue siendo opcional si Code Scanning no está disponible;
su `continue-on-error` no se aplica al guard ni al JSON.

## Alcance y aislamiento de ZAP

El plan procede de TP13C y apunta a `/health` y `/api/notes` del backend
actual. Usa PostgreSQL efímero y la imagen del build en una red Docker
**interna, sin puertos publicados** ni salida hacia objetivos externos.
La contraseña de esa base se genera en memoria y no se versiona ni publica.
Heap, memoria y CPU del escáner están acotados; se limpia el entorno al salir.
Se verifica la ruta al backend desde la propia imagen del escáner y se fija
su resolución dentro de la red privada. Java usa un home escribible también
para el runner. Se conserva el usuario zap (UID 1000) de la imagen y se
comparte únicamente el grupo del directorio privado de reportes. Un timeout de proceso preserva diagnóstico y
limpieza sin convertir un fallo en éxito.
Se usa `-silent` para evitar telemetría y comprobaciones de actualización no
solicitadas ([opción oficial ZAP](https://www.zaproxy.org/docs/desktop/cmdline/)).

Esta cobertura es del backend. **No cubre frontend, TLS/Ingress ni el login de
TP13B:** la app actual no implementa sus endpoints de autenticación/cookies.
Se consultó TP13B y no se copió una autenticación que no existe en TP12.

Si el plan ZAP termina y genera un reporte válido pero su proceso no cierra,
el reporte se conserva con process_exit_code explícito. El job mantiene ese
código no cero y bloquea deploy. Se comprueba el estado del contenedor con un
límite de tiempo; no se transforma un timeout en un análisis exitoso. El
diagnóstico distingue plan terminado, archivo presente y salida del proceso.

## Requisitos y pruebas locales

Bash, Git, Docker, Python 3.11+ con PyYAML, Helm 3.18.4 y Gitleaks 8.30.0.
Trivy 0.74.0 y Semgrep 1.177.0 para sus auditorías. Los tests del backend usan
Python 3.12 y los requirements heredados, sin cambios.
Versiones y digests de imágenes auxiliares: `security/tools.json`.

```bash
bash scripts/install-gitleaks-hook.sh
bash scripts/verificar-gitleaks.sh
python3 -m unittest discover -s scripts/tests -v
python3 scripts/validate-tp18.py
for file in scripts/*.sh security/hooks/pre-commit; do bash -n "$file"; done
actionlint .github/workflows/*.yml
helm lint devops-tp12/chart -f devops-tp12/values-prod.yaml
helm template tp16 devops-tp12/chart -f devops-tp12/values-prod.yaml
git diff --check

# En un venv Python 3.12:
pip install -r devops-tp12/app/backend/requirements-dev.txt
(cd devops-tp12/app/backend && pytest tests/ --cov=. --cov-report=term-missing -v)
```

El hook analiza sólo el diff staged; no se hereda al clonar. Su instalador
rechaza sobrescribir un hook diferente. CI y el verificador histórico recorren
todos los refs disponibles. Se mantienen exactamente las dos excepciones TP17.

Auditorías locales: `scripts/audit-gitleaks.sh`, `audit-semgrep.sh`,
`audit-threagile.sh`, `audit-zap.sh`. Esta última exige la imagen
`tp16-notes-backend:<SHA>` ya construida y no hace build. En esta VM, ejecutar
escáneres pesados **secuencialmente**. Los outputs privados, herramientas,
caches e imágenes están excluidos de Git.

Para repetir pruebas de compatibilidad, descargar los cinco `parser.py`
oficiales de la revisión fijada con nombres `<tool>-parser.py` en un directorio
ignorado y ejecutar en un venv con `defusedxml` y `html2text`:

```bash
python scripts/check-parser-compatibility.py <parser-source-dir> .security-reports
```

## Procedencia, resultados y límites

Ver [procedencia](docs/PROCEDENCIA.md) y
[matriz de preparación y evidencias](docs/TP18-PREPARACION.md).
La documentación TP15–TP17 heredada está en
[antecedentes](docs/ANTECEDENTES-TP15-TP17.md).

No se remediaron vulnerabilidades ni se cambiaron requirements, chart,
manifests para reducir findings o allowlist. Un Andon rojo por hallazgos
existentes es un resultado del control conservado.

## Pendientes para DefectDojo

1. Elegir versión y dimensionamiento; **la plataforma aún no está instalada**.
2. Definir Product, Engagement y Tests por herramienta/alcance.
3. Instalar en un entorno acordado; configurar credenciales con Secrets.
4. Confirmar parsers contra esa versión usando artifacts de un mismo run.
5. Implementar import/reimport, deduplicación, SHA/run y política de errores.
6. Acordar acceso, TLS, backups y retención antes de exponer servicios.

El repositorio nuevo no hereda los Secrets de Docker Hub/Kubernetes/PostgreSQL.
No se copian valores privados desde otros repositorios. La cobertura DAST del
frontend y la protección de ramas quedan pendientes.

## Clonar, actualizar y ejecutar

```bash
# Sólo si /home/alumno/tp18 no existe:
GIT_SSH_COMMAND='ssh -i /home/alumno/.ssh/fullrepo -o IdentitiesOnly=yes' \
  git clone git@github.com:trepiol/tp18.git /home/alumno/tp18
cd /home/alumno/tp18
git switch main
git config core.sshCommand 'ssh -i /home/alumno/.ssh/fullrepo -o IdentitiesOnly=yes'
bash scripts/install-gitleaks-hook.sh
gh workflow run cicd.yml --repo trepiol/tp18 --ref main

# Para actualizar un clon existente con árbol limpio:
git pull --ff-only origin main
```
