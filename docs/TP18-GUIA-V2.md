# Propuesta V2 de la guía TP18

## Propósito y requisitos previos

Consolidar evidencias reales de las cinco auditorías sin reducir findings ni neutralizar los Andon Cord. Separar los criterios de éxito de la gestión de vulnerabilidades de los criterios de aprobación de release.

1. Clon limpio y completo de TP18, con aplicación TP12, Helm, cinco auditorías y seis bundles validados de un mismo SHA/Run ID.
2. Docker/Compose, Bash, Python 3 con PyYAML, Git, gh, Helm 3.18.4 y Gitleaks 8.30.0. Backend probado con Python 3.12 y requirements heredados.
3. Relevar CPU/RAM/disco/volúmenes/puertos. El laboratorio se comprobó con 4 vCPU y 12 GiB RAM. Reservar al menos 8 GiB libres antes de instalar y espacio para crecimiento/backups; no confundir esta reserva práctica con un mínimo oficial universal.
4. Elegir una release estable y fijar imágenes por digest. Esta implementación validó CE 3.4.101 con PostgreSQL y Valkey del Compose oficial.
5. Aprobar el modelo de conectividad antes de configurar tokens o runners. No exponer HTTP público para conectar GitHub.

~~~bash
git status --short --branch
git log -1 --oneline
nproc
free -h
df -h /
docker ps
docker volume ls
ss -ltn
~~~

Aceptación: recursos disponibles, repositorio correcto, sin colisiones de puertos y sin necesidad de borrar datos ajenos.

## Fase 1 Build y paquete inmutable

Usar la ruta real `devops-tp12/app/backend`, no el ejemplo `./backend` de la guía. Mantener tests de la app como dependencia del build, con el lint histórico independiente. Exportar el tarball una sola vez, identificado por SHA y checksum; no reconstruir para ZAP o Trivy.

Aceptación: tests pasan; artifact de imagen y checksum corresponden al SHA. Build fallido implica omitir los jobs que necesitan esa imagen.

## Fase 2 Reportes estructurados y gates

Mantener versiones y reglas heredadas. Renderizar el chart real antes de IaC:

~~~bash
helm lint devops-tp12/chart -f devops-tp12/values-prod.yaml
helm template tp16 devops-tp12/chart -f devops-tp12/values-prod.yaml > manifests-rendered-prod.yaml
python3 -m unittest discover -s scripts/tests -v
~~~

Matriz de parsers comprobados por importación real:

| Auditoría | Formato para importar | Parser |
|---|---|---|
| ZAP | XML; conservar JSON/HTML como evidencia | ZAP Scan |
| Threagile | risks.json, lista de riesgos | Threagile risks report |
| Semgrep | JSON nativo sanitizado | Semgrep JSON Report |
| Trivy | JSON por SCA, imagen, secretos e IaC y banda | Trivy Scan |
| Gitleaks | JSON redactado, incluso lista vacía real | Gitleaks Scan |

Actualizar la sintaxis histórica Gitleaks a `gitleaks git --log-opts=--all --config .gitleaks.toml --redact=100`, con formato JSON y exit code de findings reservado por el helper. No agregar `|| true` a un análisis operativo. Diferenciar findings informativos de errores de configuración, instalación o ejecución.

Aceptación: seis bundles reales, SHA/run coincidentes, formatos/hashes válidos y ausencia de secretos publicados. Un gate rojo conserva su resultado y no impide recopilar evidencia válida. Un escáner fallido no produce un reporte vacío de reemplazo.

## Fase 3 Instancia y contexto reales

Sustituir los scripts antiguos de construcción por el Compose de una release explícita; usar imágenes oficiales precompiladas con digest para ahorrar espacio de build y fijar la implementación.

~~~bash
bash scripts/preparar-defectdojo.sh
python3 scripts/inicializar-defectdojo.py
bash scripts/defectdojo-compose.sh ps -a
~~~

Crear Product Type Aplicaciones Web DevSecOps, Product Notes App y Engagement CI/CD Automated Security Audits. Obtener IDs desde la API. Nunca fijar PRODUCT_ID=1 por conveniencia. Las equivalencias UI de esta release son Organization/Asset.

Aceptación: initializer Exited 0, base y web saludables, workers en marcha, API autenticada y jerarquía comprobada en UI/API. El usuario CI sólo accede al producto objetivo.

## Importar y reimportar con trazabilidad

Descargar artifacts de un run real. Suministrar token por archivo privado o Secrets, nunca en texto dentro del comando. El contexto privado proviene del setup:

~~~bash
export DEFECTDOJO_URL=http://127.0.0.1:8080
export DEFECTDOJO_TOKEN_FILE="$PWD/.security-private/defectdojo/api-token"
export DEFECTDOJO_PRODUCT_TYPE_ID="$(python3 -c 'import json; print(json.load(open(".security-private/defectdojo/context.json"))["product_type_id"])')"
bash scripts/verificar-defectdojo.sh check
bash scripts/verificar-defectdojo.sh import --bundles RUTA --sha SHA_COMPLETO --run-id RUN_ID
bash scripts/verificar-defectdojo.sh reimport --bundles RUTA --sha SHA_COMPLETO --run-id RUN_ID --output .security-collection/reimport
~~~

Usar import-scan sólo para el Test nuevo, reimport-scan para su ID existente. Títulos y servicios estables por herramienta/alcance; `commit_hash` y `build_id` registran procedencia. Exigir HTTP 201 y consultar el Test resultante. No buscar la palabra scan_type en una respuesta HTTP como criterio de éxito.

Comparar antes/después: Tests/IDs, total y activos, duplicados, aceptados, severidades y hash de IDs/flags. No afirmar deduplicación entre herramientas sólo porque una reimportación no crece. Mantener cierre/reactivación automáticos deshabilitados durante la prueba para no modificar estados reales.

Aceptación: mismos Tests, ningún crecimiento al reimportar idénticos reportes y estados conservados. Registrar diferencias reales de normalización si ocurren, sin inventar igualdad entre escáneres y plataforma.

## Conectividad y errores en CI

Conectar sólo el importador a la VM mediante un runner JIT confiable y desechable. Mantener los demás jobs hospedados. Excluir PR no confiables, usar environment protegido, exigir revisión del SHA y no montar credenciales del host ni Docker socket. No dejar un runner permanente conectado al repositorio público.

El importador depende del colector exitoso con `always()`. Puede importar un bundle válido aunque Trivy bloquee release. El deploy exige rama main y todos los gates originales, tests de reportes, colector e importador exitosos.

Aceptación: run real con cinco herramientas, seis bundles, importaciones/reimportaciones reales y deploy omitido si el Andon está rojo. La publicación de la imagen también queda detrás del mismo gate.

## Persistencia y operación

~~~bash
bash scripts/respaldar-defectdojo.sh
bash scripts/verificar-defectdojo.sh snapshot --output .security-collection/antes
bash scripts/defectdojo-compose.sh restart postgres valkey uwsgi celeryworker celerybeat nginx
bash scripts/verificar-defectdojo.sh snapshot --output .security-collection/despues
bash scripts/verificar-defectdojo.sh negative --output .security-collection/negativa
~~~

Aceptación: datos/IDs/estados iguales después del reinicio, archivos de backup verificados y HTTP 400 controlado sin alteración del snapshot. Documentar restauración sobre otra instancia antes de un cambio destructivo; no confundir validar el archivo con ejecutar una restauración.

Diagnóstico en orden: recursos y discos; estado/migraciones; puertos y túnel; autenticación/permisos; contexto; SHA/run/hashes; parser/formato; HTTP/estado del Test; snapshots. No imprimir tokens ni cuerpos de errores con datos sensibles. Conservar el código no cero ante errores operativos.

## Checklist de evidencias

- Identidad real de usuario/equipo/Git, repo y SHA.
- Contenedores y versión CE; jerarquía y Tests de las cinco herramientas.
- Registros de import/reimport, snapshots y hash de estados.
- Findings y severidades reales; cero Gitleaks interpretado correctamente.
- HTTP/red negativos, persistencia y archivos de backup privados.
- Run CI completo, job DefectDojo y gates rojos conservados.
- actionlint, YAML, Bash, Helm, tests de app/reportes/API, Gitleaks y diff check.
- DOCX/PDF con siete secciones en páginas nuevas, capturas auténticas y procedencia explícita.
