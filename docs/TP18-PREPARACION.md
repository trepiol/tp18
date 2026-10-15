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

## Integración CI ejecutada y comprobada

El código incorpora defectdojo-import después del colector, con always() y validación de sus prerequisitos; mantiene deploy detrás de todos los gates. Environment protegido y token configurados con autorización del usuario. El runner es JIT, aislado en contenedor y limitado a un job confiable, sin Docker socket ni credenciales del host montadas. Las 17 pruebas de scripts forman parte del CI.

La prueba completa se ejecutó en [run 38664207927](https://github.com/trepiol/tp18/actions/runs/38664207927), commit técnico `84088cbf3125713917ff326069846c851eec4216`. El job DefectDojo pasó en 1 min 9 s. Se publicaron 10 artifacts: nueve tipos heredados más el comprobante Dojo. Los reportes y comprobantes duran 14 días; la imagen heredada 1 día.

| Job o control CI | Resultado observado |
|---|---|
| Tests app / scripts | success, 7 y 17 pruebas respectivamente |
| Build único | success |
| ZAP / Threagile / Semgrep | success; 5 / 42 / 20 |
| Gitleaks Andon / auditoría | success; 0 no exceptuados |
| Trivy Andon | failure; HIGH/CRITICAL 61: SCA 3, imagen 47, IaC 11 |
| Trivy LOW/MEDIUM | success; 178: SCA 6, imagen 130, IaC 42 |
| Colector | success, 6/6 bundles |
| DefectDojo | success, doce reportes y reimportación idéntica |
| Lint histórico TP06 | failure independiente, conservado |
| Release y deploy | skipped, sin publicar imagen |

Cada run contiene 306 entradas de reportes, con su propia procedencia. Tras sincronizar el segundo SHA, Dojo tiene 469 Findings activos en los mismos 12 Tests. Sev.: High 113, Medium 194, Low 161, Info 1. Risk accepted 3 heredados; duplicados clasificados 0. No son vulnerabilidades únicas.

El parser Trivy incorpora Target con SHA en description y en su hash de identidad. Por eso 44 entradas HIGH y 119 LOW/MEDIUM del SO se conservan como registros diferentes entre las dos versiones: 306 + 163 = 469. Los pares comparados conservan CVE/paquete/versión y sólo difieren en ese SHA dentro de la descripción. No se cambió ningún reporte ni configuración de deduplicación. La reimportación idéntica del nuevo conjunto mantuvo 469 → 469, los doce Test IDs y todos los estados. Un reinicio posterior y un negativo HTTP 400 mantuvieron el mismo snapshot/hash:

`fe56e2e31c5cd10c46c85a98d14103f30a84d5a7e7ea8d4416672d5a3f9962b9`

El runner JIT se eliminó al terminar; GitHub confirmó cero runners registrados. Se comprobó un clon nuevo con hook instalado, 17 tests, grafo y Gitleaks aprobados sin copiar credenciales de instancia. El informe y los comprobantes están en [entrega](../entrega/README.md).

## Límites

Sin remediación ni ampliación de allowlists. El Andon Trivy continúa bloqueando release ante HIGH/CRITICAL. Las cantidades por ámbito pueden solaparse y no representan vulnerabilidades únicas. Un JSON Gitleaks vacío válido produce un Test sin Findings; no se inventa un secreto.

El runner requiere revisión y lanzamiento por el operador en cada run autorizado. HTTP queda dentro de loopback/SSH. No hay TLS directo ni alta disponibilidad. Se verificó el backup, pero no se restauró sobre la base real. ZAP cubre backend, no frontend/Ingress/login; Semgrep conserva PartialParsing en Bash. No se configuraron credenciales de release ajenas a TP18.

[Instalación, permisos, API y operación](TP18-DEFECTDOJO.md). [Guía V2 propuesta](TP18-GUIA-V2.md).
