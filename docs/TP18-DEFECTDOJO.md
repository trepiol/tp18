# TP18 DefectDojo CE y API v2

## Instalación reproducible

La guía del profesor propone Docker Compose. Esta implementación conserva esa arquitectura y utiliza las imágenes oficiales precompiladas de **DefectDojo CE 3.4.101** fijadas por digest. El origen y las adaptaciones están en `infra/defectdojo/upstream.json`. La versión estable seleccionada utiliza **Valkey**, compatible con Redis, como broker/cache. PostgreSQL y el resto de imágenes corresponden al Compose de esa release.

La instalación es de laboratorio. No tiene exposición pública ni TLS propio: HTTP está ligado exclusivamente a `127.0.0.1:8080`. El acceso desde otra máquina se realiza por SSH. No publicar el puerto directamente en Internet.

Comprobar primero los recursos y otros servicios:

~~~bash
nproc
free -h
df -h /
docker ps
docker volume ls
ss -ltn
~~~

En esta VM se midieron 4 vCPU, 12 GiB de RAM y 12 GiB libres antes de instalar. El instalador exige 8 GiB libres antes de descargar; el launcher de CI conserva al menos 4 GiB de reserva. Estos límites son una política del laboratorio, no un mínimo universal del fabricante. Mantener espacio adicional para crecimiento, backups y actualizaciones. No se borran volúmenes ajenos ni se usa `docker system prune`.

En un clon nuevo, con Docker Compose y Python 3:

~~~bash
bash scripts/preparar-defectdojo.sh
python3 scripts/inicializar-defectdojo.py
bash scripts/defectdojo-compose.sh ps -a
~~~

El primer arranque aplica las migraciones y puede tardar varios minutos. El initializer debe terminar con código 0. `uwsgi`, PostgreSQL y Valkey tienen healthchecks; nginx, celeryworker y celerybeat deben seguir levantados. No interpretar un contenedor `Created` durante las migraciones como una instalación terminada.

El entorno privado se genera en `.security-private/defectdojo/install.env`, permisos 600, directorio 700. No se sobrescribe al repetir el instalador. Las contraseñas aleatorias no se imprimen. La API y el servidor no registran los valores en las evidencias públicas.

Acceso autorizado desde la computadora del estudiante:

~~~bash
ssh -N -L 127.0.0.1:18081:127.0.0.1:8080 alumno@192.168.0.29
~~~

Abrir `http://127.0.0.1:18081`; usuario `admin`. Consultar la contraseña sólo en la sesión privada de la VM, fuera de capturas y grabaciones. Cerrar el túnel al terminar. No utilizar HTTP sin cifrar fuera de loopback; para otros despliegues se requiere TLS validado y control de red.

## Jerarquía y permisos

El script inicializador descubre o crea los nombres exactos; nunca presupone IDs 1. En esta instancia se obtuvieron:

| Objeto | Nombre | ID observado |
|---|---|---:|
| Product Type | Aplicaciones Web DevSecOps | 2 |
| Product | Notes App | 1 |
| Engagement | CI/CD Automated Security Audits | 1 |

El Engagement es CI/CD y está In Progress. La UI de 3.4.101 usa los términos **Organization** y **Asset** para Product Type y Product; la API mantiene `product_types` y `products`.

`tp18-api-importer` es una cuenta API sin contraseña utilizable, sin staff ni superuser. Sólo es miembro de Notes App; no es miembro del Product Type. En esta versión CE la autorización se basa en membresía: el token permite importar y editar dentro de ese producto, no es un permiso exclusivamente de importación. La cuenta no ve otros productos. El ID de categoría obtenido durante setup se suministra como metadato, porque dar acceso a toda la categoría ampliaría permisos futuros.

## Verificación local y API

Cargar el token mediante un archivo privado, nunca como argumento literal en el historial:

~~~bash
export DEFECTDOJO_URL=http://127.0.0.1:8080
export DEFECTDOJO_TOKEN_FILE="$PWD/.security-private/defectdojo/api-token"
export DEFECTDOJO_PRODUCT_TYPE_ID="$(python3 -c 'import json; print(json.load(open(".security-private/defectdojo/context.json"))["product_type_id"])')"
bash scripts/verificar-defectdojo.sh check
~~~

Para importar artifacts descargados de una ejecución real, fijar explícitamente su SHA y Run ID:

~~~bash
bash scripts/verificar-defectdojo.sh import \
  --bundles .security-bundles/run-ID --sha SHA_COMPLETO --run-id RUN_ID
bash scripts/verificar-defectdojo.sh reimport \
  --bundles .security-bundles/run-ID --sha SHA_COMPLETO --run-id RUN_ID \
  --output .security-collection/reimport
~~~

`import` exige Tests ausentes. `reimport` exige Tests existentes. `sync` crea sólo los que faltan y reimporta el resto. Un título ambiguo detiene ese reporte. Los 12 títulos estables separan ZAP, Threagile, Semgrep, Gitleaks y los cuatro ámbitos Trivy en cada banda HIGH/CRITICAL y LOW/MEDIUM.

Primero se revalidan los seis bundles con el colector existente: identidad, ejecución completa, árbol de origen limpio, SHA, Run ID, formatos y hashes. Se usan reportes estructurados, no sus manifests:

| Fuente | Parser nativo | Archivo |
|---|---|---|
| ZAP | ZAP Scan | zap-report.xml |
| Threagile | Threagile risks report | risks.json |
| Semgrep | Semgrep JSON Report | semgrep-results.json |
| Trivy | Trivy Scan | JSON SCA, imagen, secretos e IaC por banda |
| Gitleaks | Gitleaks Scan | gitleaks-report.json, incluso con cero findings |

Cada POST usa `/api/v2/import-scan/` o `/api/v2/reimport-scan/`, el Engagement real, título estable, servicio por ámbito, SHA en `commit_hash` y Run ID en `build_id`. Se exige HTTP 201, Test ID correcto, procedencia confirmada desde GET y deduplicación síncrona terminada. No se reintenta automáticamente un POST ambiguo después de un timeout: se consulta el Test por título antes de decidir.

`close_old_findings=false` y `do_not_reactivate=true` evitan cerrar o reabrir findings durante estas pruebas de consolidación. No se remedian vulnerabilidades. La reimportación idéntica compara Tests/IDs/conteos/severidades/estados y un hash de los IDs y flags individuales. La separación por servicio evita mezclar SCA, imagen, secretos e IaC; el total no se presenta como vulnerabilidades únicas entre herramientas.

Los errores HTTP, red, respuesta no JSON, configuración, hash o formato devuelven código no cero. No se imprimen bodies de errores, que podrían contener datos sensibles; un reporte fallido no se presenta como importado. Se intenta registrar el estado de los demás reportes y el resultado global falla si alguno falla.

Comprobantes seguros: `defectdojo-result.json`, snapshots y resumen con cantidades. Los reportes originales, tokens y logs privados permanecen ignorados por Git.

~~~bash
bash scripts/verificar-defectdojo.sh snapshot --output .security-collection/snapshot
bash scripts/verificar-defectdojo.sh negative --output .security-collection/negative
~~~

La prueba negativa envía un parser inválido, exige HTTP 400 y verifica que el snapshot no cambie. Para demostrar un fallo real de conectividad se usó loopback puerto 1: el verificador devolvió código 1; no se alteró la instancia.

## GitHub Actions y conectividad

El usuario autorizó el runner efímero y el token protegido. Los runners hospedados no pueden acceder directamente a la LAN. Sólo el job `defectdojo-import` usa un runner JIT en un contenedor desechable de la VM; los escáneres permanecen hospedados en GitHub.

- `needs`: colector y pruebas de reportes, ambos exitosos; condición `always()` para admitir un Andon Trivy rojo.
- Se excluye `pull_request`; sólo se admiten main y la rama de implementación del propietario.
- Environment `tp18-defectdojo`: revisión del propietario, ramas permitidas y token `DEFECTDOJO_API_KEY` cifrado por GitHub. Variable `TP18_PRODUCT_TYPE_ID` observada, no supuesta.
- Todos los workflows de colaboradores externos requieren aprobación. No aprobar código de terceros para este runner.
- El launcher verifica actor, repositorio, workflow, evento, rama, SHA revisado y checkout limpio. Rechaza jobs self-hosted competidores y aprueba únicamente el environment de esa ejecución revisada.
- El runner ejecuta un solo job y se elimina; sin claves SSH, home del usuario, directorios del host ni socket Docker montados. Capabilities eliminadas, sin elevación de privilegios, memoria/CPU/procesos acotados.
- El contenedor comparte la red para acceder a loopback. No debe ejecutar código no confiable; el aislamiento no reemplaza la revisión. GitHub desaconseja runners self-hosted permanentes en repositorios públicos.

Construir una vez la imagen de infraestructura (no reconstruye Notes App):

~~~bash
docker build -t tp18-dojo-runner:validated infra/defectdojo/runner
~~~

Después de revisar y publicar un commit confiable en la rama autorizada, esperar a que el colector termine y el job solicite el environment. Desde el clon limpio del mismo SHA:

~~~bash
python3 scripts/ejecutar-runner-defectdojo.py --run-id RUN_ID --sha SHA_COMPLETO
~~~

Es una conexión operada bajo demanda, sin servicio runner persistente. Cada nueva ejecución requiere revisión y lanzamiento del runner. No se habilita un consumidor permanente de PR públicos. En CI se ejecutan `sync` y una segunda reimportación idéntica, con comprobantes de 14 días. Ningún éxito de importación modifica el Andon; deploy exige todos sus controles originales más los tests de reportes y DefectDojo.

## Persistencia y respaldos

Volúmenes exclusivos del proyecto `tp18-defectdojo`: PostgreSQL, media y broker/cache. Los servicios tienen `unless-stopped`; el inicializador es de una ejecución. No usar `down --volumes` sobre la instancia con datos.

~~~bash
bash scripts/respaldar-defectdojo.sh
bash scripts/defectdojo-compose.sh restart postgres valkey uwsgi celeryworker celerybeat nginx
bash scripts/verificar-defectdojo.sh check
bash scripts/verificar-defectdojo.sh snapshot --output .security-collection/despues-reinicio
~~~

Los respaldos privados contienen `pg_dump -Fc`, media y las claves de configuración. Se validan con `pg_restore --list`, `tar -tzf` y SHA-256. Política básica: respaldo antes de cambios/importaciones relevantes y diario mientras se use el laboratorio; conservar siete copias privadas fuera de Git y una copia cifrada en otro volumen. La rotación debe ser manual y revisada; este trabajo no borra backups automáticamente.

Restauración propuesta, **sólo con autorización y preferentemente sobre otra instancia aislada**:

1. Verificar hashes y reservar espacio; preservar la instancia actual.
2. Usar la misma release/digests y las claves privadas originales.
3. Iniciar una base PostgreSQL vacía aislada y restaurar con `pg_restore --exit-on-error --no-owner -U defectdojo -d defectdojo` desde el dump.
4. Restaurar media en su volumen aislado y permisos de la imagen.
5. Iniciar Django/workers, verificar API, jerarquía, snapshots y reportes.
6. Coordinar el cambio de acceso sólo después de verificar los datos.

No se restauró sobre la base en uso ni se ejecutaron reescrituras destructivas. La prueba de persistencia compara snapshots antes/después del reinicio; validar archivos de backup no equivale a probar una restauración completa.

## Fuentes oficiales

- [DefectDojo CE release 3.4.101](https://github.com/DefectDojo/django-DefectDojo/releases/tag/3.4.101).
- [Compose de esa release](https://github.com/DefectDojo/django-DefectDojo/blob/3.4.101/docker-compose.yml).
- [Instalación Open Source](https://docs.defectdojo.com/get_started/open_source/installation/).
- [Serializadores API de la release](https://github.com/DefectDojo/django-DefectDojo/blob/3.4.101/dojo/api_v2/serializers.py).
- [Seguridad de runners GitHub](https://docs.github.com/en/actions/reference/security/secure-use).
