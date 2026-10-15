# Entrega universitaria TP18

Autor: Ezequiel Cuya. Validación técnica: 14 de octubre de 2026 (Argentina); cierre documental: 15 de octubre de 2026.

**Commit técnico:** `84088cbf3125713917ff326069846c851eec4216`. **Run:** [38664207927](https://github.com/trepiol/tp18/actions/runs/38664207927). Los documentos se agregan después; no se atribuye ese run al commit posterior de documentación.

- [DOCX editable](TP18_Informe_Final.docx).
- [PDF](TP18_Informe_Final.pdf).

19 páginas; portada, índice enlazado, siete secciones con saltos reales, doce capturas auténticas, propuesta V2 y demostración en clase. Los archivos de capturas se conservan completos; Word sólo recorta su presentación para legibilidad. Ninguna pantalla fue simulada.

## Procedencia de capturas

| Figura | Evidencia real | Momento o ejecución |
|---|---|---|
| 1 | [Identidad VM, Git y commit](capturas/figura-01-terminal-identidad.jpg) | VM real / validación local |
| 2 | [Compose y siete servicios](capturas/figura-02-terminal-contenedores.jpg) | VM real / validación local |
| 3 | [Producto y categoría en UI](capturas/figura-03-dojo-producto.jpg) | run 38512049385, SHA 7e39cc4 |
| 4 | [Importación inicial API](capturas/figura-04-terminal-importacion.jpg) | run 38512049385, SHA 7e39cc4 |
| 5 | [Reimportación inicial idéntica](capturas/figura-05-terminal-reimportacion.jpg) | run 38512049385, SHA 7e39cc4 |
| 6 | [Gitleaks, Semgrep y Threagile en UI](capturas/figura-06-dojo-tres-herramientas.jpg) | run 38664207927, SHA 84088cb |
| 7 | [ZAP y Trivy, total 469 en UI](capturas/figura-07-dojo-zap-trivy.jpg) | run 38664207927, SHA 84088cb |
| 8 | [Job DefectDojo aprobado en GitHub](capturas/figura-08-github-defectdojo.jpg) | run 38664207927, SHA 84088cb |
| 9 | [Estados del run mediante gh](capturas/figura-09-terminal-ci-estados.jpg) | run 38664207927, SHA 84088cb |
| 10 | [17 pruebas de scripts ejecutadas](capturas/figura-10-terminal-tests.jpg) | VM real / validación local |
| 11 | [7 tests app y cobertura](capturas/figura-11-terminal-app.jpg) | VM real / validación local |
| 12 | [Persistencia y negativos HTTP/red](capturas/figura-12-terminal-persistencia-errores.jpg) | run 38664207927, SHA 84088cb |

## Interpretación de conteos

Cada colección de escáneres tiene 306 entradas: ZAP 5, Threagile 42, Semgrep 20, Trivy HC 61, Trivy LM 178, Gitleaks 0. Dojo conserva 12 Tests y 469 registros activos acumulados de dos Targets. Reimportación idéntica: 469 → 469, mismos IDs y estados. No son vulnerabilidades únicas. El parser Trivy incorpora Target con SHA en description/hash; 163 entradas OS reciben identidad diferente entre las dos versiones. Se conserva esa limitación sin editar reportes ni eliminar Findings.

## Archivos publicables

Los JSON aquí guardados son comprobantes de contexto, conteos, hashes, metadatos CI, containers y manifests. No se versionan los reportes crudos, tokens, dumps o configuración privada. Las salidas 5/6 o 0/6 de los unit tests son negativos intencionales, no el resultado del colector CI. El harness con stubs verifica formatos; las pruebas API reales están en initial/ci_sync/ci_reimport.

La recolección ocurrió mientras los artifacts seguían vigentes; reportes y comprobantes expiran a los 14 días, imagen al día. hashes.sha256 identifica los archivos de esta entrega.

La persistencia y los archivos de backup se comprobaron; no se ejecutó restauración destructiva ni se automatizó su cron. Cada runner JIT exige revisión y lanzamiento del operador. La integración a main requiere autorización de cierre.
