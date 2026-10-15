# TP18 Matriz de implementación y evidencias

El antecedente de preparación se conserva en [documento histórico](TP18-PREPARACION-ANTECEDENTE.md). Sus pendientes corresponden a aquella fase previa.

## Estado comprobado localmente

| Control | Resultado real |
|---|---|
| Instancia | CE 3.4.101, Compose oficial adaptado y digests; PostgreSQL y Valkey persistentes |
| Red | nginx sólo en 127.0.0.1:8080; acceso SSH; sin servicio público |
| Jerarquía | Product Type Aplicaciones Web DevSecOps ID 2; Notes App ID 1; Engagement CI/CD Automated Security Audits ID 1 |
| Permisos | Cuenta API-only miembro sólo del producto; sin staff, superuser o membresía de categoría |
| Importación inicial | 12/12 reportes, HTTP 201, Tests 1 a 12, 306 Findings activos del run 38512049385 |
| Reimportación idéntica | 12 Tests y 306 Findings; duplicados 0; estados/IDs conservados |
| Riesgos aceptados | 3 de Threagile ya presentes en el modelo; se mantienen |
| Persistencia | Reinicio de seis servicios; snapshot y hash de IDs/estados idénticos |
| Errores controlados | HTTP 400 sin cambios de datos; puerto loopback cerrado devuelve exit 1 |
| Backup | pg_dump custom, media y entorno privado; pg_restore --list, tar y hashes verificados |
| Scripts | 17 tests: 11 de reportes + 6 del cliente API; Bash/YAML/actionlint válidos |
| App | 7 tests Python 3.12, cobertura total 90 % y app.py 85 % |
| Helm | Lint pasa; render de producción idéntico al heredado |
| Gitleaks | Historial completo 0 no exceptuados; dos excepciones originales intactas |
| Preservación | App, requirements, chart, manifests, Semgrep y jobs Trivy conservados |

Los reportes iniciales pertenecen al SHA `7e39cc4986b3d8207299e4e0f8ce3300ec973ccd` y [run 38512049385](https://github.com/trepiol/tp18/actions/runs/38512049385). Los nuevos runs deben registrar sus propios conteos y procedencia.

## Integración CI por ejecutar en esta revisión

El código incorpora defectdojo-import después del colector, con always() y validación de sus prerequisitos; mantiene deploy detrás de todos los gates. Environment protegido y token configurados con autorización del usuario. El runner es JIT, aislado en contenedor y limitado a un job confiable, sin Docker socket ni credenciales del host montadas. Las 17 pruebas de scripts forman parte del CI.

La prueba completa y sus conteos se registrarán después de ejecutarla. No se considera una importación CI exitosa antes de comprobarla.

## Límites

Sin remediación ni ampliación de allowlists. El Andon Trivy continúa bloqueando release ante HIGH/CRITICAL. Las cantidades por ámbito pueden solaparse y no representan vulnerabilidades únicas. Un JSON Gitleaks vacío válido produce un Test sin Findings; no se inventa un secreto.

El runner requiere revisión y lanzamiento por el operador en cada run autorizado. HTTP queda dentro de loopback/SSH. No hay TLS directo ni alta disponibilidad. Se verificó el backup, pero no se restauró sobre la base real. ZAP cubre backend, no frontend/Ingress/login; Semgrep conserva PartialParsing en Bash. No se configuraron credenciales de release ajenas a TP18.

[Instalación, permisos, API y operación](TP18-DEFECTDOJO.md). [Guía V2 propuesta](TP18-GUIA-V2.md).
