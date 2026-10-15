# TP18 — Matriz de preparación

Base TP17: `7072a9b`. Destino independiente: `trepiol/tp18`.
No se instala ni integra DefectDojo en esta fase.

## Implementado y probado

| Control | Evidencia |
|---|---|
| Independencia Git | Nuevo clon con historial; main; fuente TP17 limpia y sin cambios |
| Gitleaks 8.30.0 | Historial completo: 0 no exceptuados; configuración original y dos excepciones intactas |
| Gitleaks negativo | Reproducción temporal del archivo histórico TP09: CLI código 1, un finding; JSON sanitizado aceptado por el parser oficial como un finding |
| Pruebas de reportes | 11 tests: redacción, campos del parser, formatos inválidos, warnings y bundles ausentes |
| App integrada | 7 tests pasan en Python 3.12; cobertura total 90 %, app.py 85 % |
| Helm | Lint pasa; YAML de producción válido, reproducible e igual al heredado |
| Threagile | risks.json real: 42 riesgos; PDF y dos diagramas; parser devuelve 42; job CI exitoso |
| Semgrep | 20 findings reales; JSON/SARIF sanitizados; parser devuelve 20; guard ERROR y job CI pasan |
| ZAP 2.17.0 | Local y CI pasan: 5 alertas, JSON/XML/HTML sanitizados; parser XML devuelve 5 |
| Trivy HIGH/CRITICAL | CI: 61 findings (SCA 3, imagen 47, IaC 11, secretos 0); Andon rojo y artifact publicado |
| Trivy LOW/MEDIUM | CI: 178 findings (SCA 6, imagen 130, IaC 42, secretos 0); auditoría exitosa |
| Workflows | actionlint 1.7.12; YAML y Bash válidos; dependencias y condiciones comprobadas |
| Preservación | App, requirements, chart, perfil de producción y allowlist sin cambios |

Los conteos reflejan las ejecuciones de referencia documentadas abajo y pueden
cambiar con nuevas bases de vulnerabilidades, reglas o imágenes base. El índice
de cada run valida los seis bundles del mismo SHA y no sustituye un reporte
inexistente con datos vacíos. El estado definitivo de cada ejecución se consulta
en su índice y jobs, incluso cuando el workflow global queda rojo por un gate.

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
- PostgreSQL tardaba en sincronizar su directorio durante el arranque local:
  la base efímera DAST usa tmpfs de 512 MiB; producción no cambia.
- ZAP intentaba telemetría/actualizaciones sin salida de red: se agrega
  -silent, sin desactivar spiders, análisis pasivo o activo.

## Diagnóstico adicional del runner

Las dos primeras ejecuciones agotaron el límite de ZAP. La tercera ejecución
registró código 124, fase automation, 726 segundos y cero indicadores de DNS,
permisos o memoria en stdout. No se declara una causa de fondo no comprobada.
El control se adapta a inspeccionar el estado nativo del contenedor, acotar su
duración y publicar sólo diagnóstico seguro. Un plan realmente finalizado y
su reporte válido pueden conservarse aunque falle el cierre del proceso;
ese fallo continúa visible en el manifest y el job y bloquea deploy.

El diagnóstico siguiente no registró jobs del plan ni JSON. Por eso se
conserva el usuario estándar de la imagen ZAP (UID 1000), se valida escritura
en /zap, /home/zap y el volumen privado, y se comparte sólo el grupo del
runner. Los logs privados de aplicación se acotan y su lectura tiene timeout.

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

Primera ejecución real: [38505408582](https://github.com/trepiol/tp18/actions/runs/38505408582),
SHA **bf96876f0344c95a19b7970d08ec125bcb605207**.
Se descargaron y validaron con parsers oficiales los bundles Gitleaks,
Semgrep, Threagile y ambos Trivy de esa ejecución. El guard Trivy falla por
findings y conserva su artifact; el lint TP06 también falla como antecedente
independiente. ZAP quedó demorado en la configuración anterior a -silent;
su resultado no se declara exitoso por anticipado.

La versión final incorpora -silent y versión ZAP comprobada, más sanitización
de ImageConfig/mensajes Trivy y rangos Gitleaks. Conserva IDs, paquetes,
severidades y conteos: se compararon 61 HIGH/CRITICAL y 178 LOW/MEDIUM sin
cambios. El parser Gitleaks conserva dos findings redactados en una misma
línea cuando sus rangos difieren.

[Ejecuciones del workflow final](https://github.com/trepiol/tp18/actions/workflows/cicd.yml?query=branch%3Amain).
La evidencia de cualquier ejecución posterior queda en sus artifacts y en
collection-index.json, con SHA/run explícitos. Para descargar y comprobar el
último run de main, desde el clon limpio actualizado:

~~~bash
tp18_run_id=$(gh run list --workflow cicd.yml --branch main --limit 1 \
  --json databaseId --jq '.[0].databaseId')
gh run download "$tp18_run_id" --pattern 'tp18-*' \
  --dir ".security-bundles/run-$tp18_run_id"
GITHUB_SHA="$(git rev-parse HEAD)" GITHUB_RUN_ID="$tp18_run_id" \
  python3 scripts/security_report.py collect \
  ".security-bundles/run-$tp18_run_id" .security-collection
~~~

El colector termina en cero sólo con seis bundles válidos del SHA/run pedidos.
Ese cero valida evidencias, no convierte el Andon rojo en verde. La plataforma
DefectDojo sigue pendiente aunque la recopilación pase.

## Cierre comprobado en GitHub Actions

Implementación validada en [run 38511623891](https://github.com/trepiol/tp18/actions/runs/38511623891),
SHA **16ce3ff70606de40379fbaab20fa67479f5eabf2**.

- Tests y build exitosos; el backend se construye una sola vez.
- ZAP exitoso: 5 alertas, salida nativa 0 y plan completo.
- Threagile exitoso: 42 riesgos; PDF y ambos diagramas presentes.
- Semgrep exitoso: 20 findings; guard ERROR y carga SARIF pasan.
- Gitleaks Andon/auditoría exitosos: 0 no exceptuados.
- Trivy Andon rojo: 61 HIGH/CRITICAL; su artifact se publica.
- Auditoría Trivy exitosa: 178 LOW/MEDIUM.
- Colector exitoso: 6/6 bundles, SHA/run y hashes válidos, sin reportes ausentes.
- Deploy omitido por el Andon rojo; lint TP06 sigue fallando como antecedente.
- Parsers oficiales leen todos los JSON correspondientes y el XML ZAP.
- Un clon nuevo desde GitHub conservó historial, instaló el hook y pasó el
  verificador Gitleaks con árbol limpio.

El arranque de ZAP quedó operativo al conservar el usuario zap (UID 1000) de
la imagen, con acceso verificado a sus directorios y al volumen privado. El
diagnóstico de CI registra salida 0 y los checks de arranque exitosos. Los
intentos anteriores permanecen disponibles, incluidos sus índices 5/6 que
identifican el artifact ausente; no se borraron ni reemplazaron evidencias.

Artifacts reales de esa ejecución (todos con el SHA indicado):

| Artifact | Contenido | Retención |
|---|---|---|
| tp16-backend-image-SHA | Tarball Docker y checksum | 1 día |
| tp18-gitleaks-SHA | JSON seguro y manifest | 14 días |
| tp18-semgrep-SHA | JSON, SARIF y manifest | 14 días |
| tp18-threagile-SHA | risks.json, PDF, dos PNG y manifest | 14 días |
| tp18-trivy-high-SHA | Cuatro JSON, YAML renderizado y manifest | 14 días |
| tp18-trivy-low-SHA | Cuatro JSON, YAML renderizado y manifest | 14 días |
| tp18-zap-SHA | JSON, XML, HTML y manifest | 14 días |
| tp18-zap-diagnostic-SHA | Metadatos operativos, sin logs crudos | 14 días |
| tp18-collection-SHA | Índice de evidencia con estados de jobs | 14 días |

Las revisiones posteriores de documentación vuelven a ejecutar el pipeline y
producen sus propios artifacts: el enlace del workflow y el comando de descarga
anterior permiten comprobar el SHA más reciente. Esta ejecución es evidencia
de referencia, no una dependencia permanente de runs históricos.

Estado final de la preparación: implementado y probado. No se instaló
DefectDojo ni se hicieron importaciones. Siguen pendientes la instancia, su
configuración, la validación API/ORM de esa versión y los Secrets de release.
La cobertura DAST sigue siendo backend; el aviso PartialParsing de Semgrep en
Bash se conserva como limitación. No se remediaron vulnerabilidades.
