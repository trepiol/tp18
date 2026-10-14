# Procedencia TP18

Base conservada con historial: TP17
`7072a9bf2e5b7aeab98cc568b2be2a299c3e686f`, rama `feature/tp17-gitleaks`.
Nuevo directorio `/home/alumno/tp18`, main independiente. Los repositorios
anteriores sólo se consultan; no reciben cambios de código, commits o pushes.

| Repositorio | Ruta original / revisión | Destino o decisión |
|---|---|---|
| trepiol/tp17 | feature/tp17-gitleaks, 7072a9b | Base con historial completo; remoto de TP17 eliminado del nuevo clon |
| trepiol/tp13c | guia-13/zap.yaml, b8c304e5bf6571c8324b48a38e7aa9562543239a | security/zap/zap.yaml adaptado al backend TP12 y Docker interno |
| trepiol/tp13c | .github/workflows/autoscan.yml; guia-13/k8s/04-zap-job.yaml; guia-13/scripts/extract-zap-reports.sh; verificar-tp13c.sh | Inspeccionados; zap-audit y audit-zap.sh sustituyen cluster, extractores y builds históricos que no corresponden |
| trepiol/TP13B-OWASP-ZAP-GithubActions | .github/workflows/zap-security.yml; .zap/zap-plan.yml | Consultados; no copiados porque TP12 no tiene login/session |
| trepiol/TP14 | devops-tp12/threagile.yaml, afe1fa2ec855f5da9caa2686baaf810e49bf20ee | Misma ruta; título y descripciones actualizados a la arquitectura/pipeline actuales |
| trepiol/TP14 | .github/workflows/cicd.yml, job threat-modeling | Recuperado con imagen 1.0.0 fijada por digest; risks.json, PDF y diagramas |
| trepiol/tp15 | .github/workflows/semgrep.yml | Heredado vía TP17 y consultado; convertido en reusable, conservando configuraciones y guard |
| trepiol/tp16 | cicd.yml; scripts/preparar-trivy-sca.sh; verificar-trivy.sh; chart; values-prod.yaml; manifests-rendered-prod.yaml | Heredados vía TP17 y contrastados; mismo build y umbrales, salidas JSON sanitizadas |
| trepiol/tp17 | .gitleaks.toml; verificar-gitleaks.sh; Andon; auditoría; hook local | Config y excepciones intactas; reporte compatible, hook versionado e instalador reproducible |
| DefectDojo/django-DefectDojo | dojo/tools/{zap,threagile,semgrep,trivy,gitleaks}/parser.py, 7448b33e1232b207af76f0e414e19e0ef2d6bfd7 | Lectores inspeccionados y probados; fuentes en cache ignorada; sin instalar Dojo |
| TP18 | scripts/security_report.py; tests; validate-tp18.py; recopilación | Validación, redacción, manifests, checksums y detección de reportes ausentes |

No se copian repositorios completos adicionales ni carpetas .git anidadas.
El modelo conserva los activos de TP14: cliente, Ingress, frontend, backend,
PostgreSQL y observabilidad. Las referencias al backend histórico se actualizan
al build único TP12; las aceptaciones de riesgo no se amplían.

Fuentes primarias:
[ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/),
[Threagile](https://github.com/Threagile/threagile),
[parsers oficiales fijados](https://github.com/DefectDojo/django-DefectDojo/tree/7448b33e1232b207af76f0e414e19e0ef2d6bfd7/dojo/tools).
