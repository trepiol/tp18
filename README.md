# TP18 Gestión centralizada con OWASP DefectDojo

Repositorio independiente de **trepiol/tp18**, basado en TP17 `7072a9b` con su historial. Aplicación: Notes App de `devops-tp12`.

**DefectDojo CE 3.4.101 está instalado** con Compose, volúmenes persistentes y API v2. Se probaron importación inicial, reimportación idéntica, errores operativos y persistencia. La integración CI se implementa en `feature/tp18-defectdojo-final`; la ejecución completa y sus resultados se registran en la [matriz de evidencias](docs/TP18-PREPARACION.md).

## Cuatro fases

1. **Build & Package:** tests TP12 y un único build del backend. Tarball Docker por SHA y checksum. El lint histórico TP06 permanece independiente.
2. **Security Audits:** ZAP, Threagile, Semgrep, Trivy y Gitleaks generan reportes del mismo SHA/run. ZAP y Trivy cargan el mismo tarball, sin reconstruir. Semgrep, Threagile y Gitleaks no dependen del build ni de Trivy.
3. **Vulnerability Management:** el colector valida seis bundles; la API importa/reimporta con parsers nativos y Tests estables por herramienta/ámbito. Un runner JIT efímero autorizado conecta sólo este job con la VM.
4. **Release & Deploy:** main y éxito de todos los gates originales, tests de reportes, colector e importador. Se conservan las comprobaciones de credenciales y Kubernetes/PostgreSQL.

## Matriz de herramientas y controles

| Herramienta | Parser nativo / reporte | Política | Artifact |
|---|---|---|---|
| ZAP 2.17.0 | ZAP Scan / XML; conserva JSON y HTML | Findings informativos; error operativo bloquea | tp18-zap-SHA |
| Threagile 1.0.0 | Threagile risks report / risks.json; PDF y diagramas | Riesgos informativos; error operativo bloquea | tp18-threagile-SHA |
| Semgrep 1.177.0 | Semgrep JSON Report / JSON y SARIF derivado | Guard OWASP ERROR heredado bloqueante | tp18-semgrep-SHA |
| Trivy 0.74.0 | Trivy Scan / JSON SCA, imagen, secretos e IaC | HIGH/CRITICAL bloquean; LOW/MEDIUM informativos | tp18-trivy-high-SHA y tp18-trivy-low-SHA |
| Gitleaks 8.30.0 | Gitleaks Scan / JSON redactado | Andon bloqueante y auditoría informativa | tp18-gitleaks-SHA |
| DefectDojo CE 3.4.101 | API v2 / import-scan y reimport-scan | Fallos operativos bloquean release; no neutraliza gates | tp18-defectdojo-SHA |

Reportes, índice y comprobantes: 14 días. Imagen heredada `tp16-backend-image-SHA`: 1 día. Cada manifest registra herramienta, versión, SHA, Run ID, conteos, warnings y hashes. No se inventan JSON vacíos ante errores. Los datos sensibles y snippets se redactan sin cambiar IDs, severidades o cantidades de Trivy.

El parser ZAP usa **XML**, comprobado por importación real; el JSON se conserva como evidencia. Gitleaks preserva Description y ubicaciones para el parser, con Secret/Match/Message REDACTED. Cero hallazgos reales produce un Test válido sin Findings.

## Comportamiento ante fallos

- **Trivy rojo o Gitleaks rojo:** las auditorías informativas y el colector siguen sus condiciones always(); si los seis bundles son válidos, DefectDojo los procesa. Publicar/importar evidencia no convierte el gate en verde.
- **Build fallido/skipped:** Trivy y ZAP se omiten; el colector detecta sus bundles ausentes y falla; DefectDojo no intenta importar una colección incompleta. Las auditorías independientes siguen.
- **Escáner, hash, parser, API o red fallidos:** error explícito y código no cero. No se declara una importación que no ocurrió.
- **Deploy/publicación:** permanecen bloqueados si falla cualquier control requerido.

Semgrep conserva auto y las cinco configuraciones explícitas. PartialParsing no fatal en `guia-11/operaciones.sh` permanece como limitación de cobertura. El SARIF opcional no modifica el guard ni el JSON. `semgrep.yml` es reutilizable sin duplicar auditorías por push/PR; no se modifica en esta fase.

ZAP evalúa `/health` y `/api/notes` en el backend de TP12, con PostgreSQL efímero, red interna sin puertos publicados, imágenes fijadas y recursos acotados. No cubre frontend, TLS/Ingress ni el login de TP13B. Conserva el usuario zap UID 1000 y checks de escritura/conectividad. Un timeout conserva diagnóstico seguro y su fallo; no se transforma en éxito.

## Instancia DefectDojo

[Instalación reproducible, permisos, API y backup](docs/TP18-DEFECTDOJO.md). [Propuesta de guía V2](docs/TP18-GUIA-V2.md).

Se obtuvieron IDs reales: Product Type **2**, Notes App **1**, Engagement **1**. La UI denomina Organization/Asset a Product Type/Product. Los artifacts de referencia del [run 38512049385](https://github.com/trepiol/tp18/actions/runs/38512049385), SHA `7e39cc4986b3d8207299e4e0f8ce3300ec973ccd`, produjeron **12 Tests y 306 Findings activos**; 3 riesgos aceptados de Threagile conservan ese estado. La reimportación idéntica mantuvo Tests, Findings e IDs/estados; duplicados 0. Los totales por ámbito pueden solaparse: no son vulnerabilidades únicas entre herramientas. Cada run nuevo debe registrar sus propios valores.

La cuenta API no es staff ni superuser y sólo pertenece a Notes App, no a toda la categoría. En CE su permiso es por producto, no exclusivamente de importación. El token está cifrado en el environment protegido `tp18-defectdojo`; no se publica.

El servidor escucha sólo en loopback. Acceso autorizado desde la computadora del estudiante:

~~~bash
ssh -N -L 127.0.0.1:18081:127.0.0.1:8080 alumno@192.168.0.29
~~~

Abrir `http://127.0.0.1:18081`. Consultar la contraseña admin únicamente en la sesión privada de la VM, sin capturas. No hay exposición pública.

El runner es JIT para un solo job, sin Docker socket, claves SSH ni directorios del usuario montados. Cada run confiable exige revisión del SHA y lanzamiento mediante `scripts/ejecutar-runner-defectdojo.py`. Se excluyen PR no confiables y se exige aprobación para workflows de colaboradores externos. No se deja un runner permanente escuchando PR públicos.

## Verificaciones

Bash, Git, Docker/Compose, Python 3.11+ con PyYAML, Helm 3.18.4, Gitleaks 8.30.0 y actionlint. Backend: Python 3.12 y requirements heredados. Digests de escáneres: `security/tools.json`; DefectDojo: `infra/defectdojo/compose.yml`.

~~~bash
bash scripts/install-gitleaks-hook.sh
bash scripts/verificar-gitleaks.sh
python3 -m unittest discover -s scripts/tests -v
python3 scripts/validate-tp18.py
for file in scripts/*.sh security/hooks/pre-commit; do bash -n "$file"; done
actionlint
helm lint devops-tp12/chart -f devops-tp12/values-prod.yaml
helm template tp16 devops-tp12/chart -f devops-tp12/values-prod.yaml
git diff --check
~~~

Hay 17 tests de scripts: 11 de reportes y 6 del cliente API, incorporados al CI. La app conserva 7 tests; en Python 3.12 se midió 90 % de cobertura total y 85 % de app.py.

El hook local analiza staged; no se hereda al clonar. El verificador histórico y CI recorren el historial completo. Se conservan exactamente las dos excepciones TP17. Los negativos usan evidencia histórica temporal y redactada, sin introducir secretos en commits.

El harness de parsers con stubs se conserva como validación de formato; por separado existen importaciones/reimportaciones reales en CE 3.4.101. No se confunden ambas pruebas.

## Alcance y antecedentes

No se remediaron vulnerabilidades, cambiaron requirements/manifests para reducir findings ni ampliaron allowlists. Los jobs Trivy y Semgrep permanecen intactos en esta fase. Antecedentes: [preparación original](docs/TP18-PREPARACION-ANTECEDENTE.md), [procedencia](docs/PROCEDENCIA.md) y [TP15 a TP17](docs/ANTECEDENTES-TP15-TP17.md).

Los respaldos contienen datos y claves privadas, quedan fuera de Git y se verifican por estructura y hashes. Se probó persistencia tras reinicio; no se restauró sobre la base en uso. Quedan como mejoras TLS directo, alta disponibilidad, restauración aislada completa y cobertura DAST adicional. No se copian Secrets de release desde repositorios anteriores ni se modifica su infraestructura.
