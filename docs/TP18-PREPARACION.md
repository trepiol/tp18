# TP18 — Matriz de preparación

Base TP17: `7072a9b`. Destino independiente: `trepiol/tp18`.
No se instala ni integra DefectDojo en esta fase.

## Implementado y probado

| Control | Evidencia |
|---|---|
| Independencia Git | Nuevo clon con historial; main; fuente TP17 limpia y sin cambios |
| Gitleaks 8.30.0 | Historial completo: 0 no exceptuados; configuración original y dos excepciones intactas |
| Gitleaks negativo | Reproducción temporal del archivo histórico TP09: CLI código 1, un finding; JSON sanitizado aceptado por el parser oficial como un finding |
| Pruebas de reportes | 9 tests: redacción, campos del parser, formatos inválidos, warnings y bundles ausentes |
| App integrada | 7 tests pasan en Python 3.12; cobertura total 90 %, app.py 85 % |
| Helm | Lint pasa; YAML de producción válido, reproducible e igual al heredado |
| Threagile | risks.json real: 42 riesgos; PDF y dos diagramas; parser devuelve 42 |
| Semgrep | 20 findings reales; JSON/SARIF sanitizados; parser devuelve 20; guard ERROR pasa |
| Workflows | actionlint 1.7.12; YAML y Bash válidos; dependencias y condiciones comprobadas |
| Preservación | App, requirements, chart, perfil de producción y allowlist sin cambios |

Los resultados de ZAP, Trivy y GitHub Actions se incorporan a la sección de
evidencias al completar sus ejecuciones; no se declaran probados sólo porque
su configuración existe.

## Problemas encontrados y soluciones

- ZAP Scan requiere XML: se conserva JSON tradicional y se genera XML
  equivalente sanitizado para ese parser.
- El reporte Gitleaks anterior omitía Description: se agregan campos de
  estructura seguros; Secret/Match/Message siguen REDACTED.
- Threagile falló al generar Excel por título largo: se acortó a Notes App
  TP18 y se repitió con éxito, sin alterar riesgos.
- Semgrep emite PartialParsing no fatal en guia-11/operaciones.sh: se conserva
  el warning y su ruta; la cobertura de ese archivo es incompleta.
- El spider ZAP visitaba / y recibía 404: se fija el contexto al endpoint
  /api/notes que existe en TP12.
- La descarga de Trivy DB sufrió connection reset by peer: es un fallo
  operativo, no un scan sin hallazgos; no se produjo un reporte vacío.
- La VM perdió conectividad durante auditorías anteriores. Tras recuperarla,
  se ejecutan los escáneres pesados de a uno y se acotan heap/CPU de ZAP.

## Alcance de compatibilidad

Lectores oficiales fijados en
`7448b33e1232b207af76f0e414e19e0ef2d6bfd7`, ejecutados con stubs de
Finding/Endpoint. Se prueba lectura real de formatos; no ORM, API, permisos,
import/reimport o deduplicación persistente. La futura versión instalada debe
revalidarse.

## Dependencias externas y límites

- Secrets nuevos para Docker Hub, Kubernetes y PostgreSQL del destino.
- Disponibilidad/permisos de GitHub Code Scanning para el SARIF opcional.
- Red y almacenamiento para bases de vulnerabilidades y releases oficiales.
- ZAP cubre backend; frontend, Ingress/TLS y autenticación futura no se
  consideran escaneados. TP13B no corresponde al contrato de TP12.
- Los findings HIGH/CRITICAL pueden dejar rojo el Andon y omitir deploy.
  No se remedia ni se agregan excepciones para obtener un pipeline verde.

## Pendiente de la fase DefectDojo

Versión/dimensionamiento, instalación, Product/Engagement/Tests,
credenciales, validación contra los parsers instalados, import/reimport,
deduplicación, trazabilidad, política de fallos, TLS, backups y retención.
No hubo importaciones simuladas ni servicios expuestos.

## Evidencias de ejecución

Pendiente de completar con los runs reales, SHA y artifacts verificables.
