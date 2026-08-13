# PhishProtect — Sprints e Historias de Usuario

**Repositorio:** https://github.com/lemarunico2020/Heroku_PhishProtect
**Alcance:** mejoras de calidad de IOCs, features para ML, rendimiento y despliegue en Docker/EasyPanel.
**Fuera de alcance (backlog futuro, no incluido aquí):** persistencia de resultados en base de datos, enriquecimiento externo (VirusTotal/AbuseIPDB/WHOIS) y cola asíncrona — quedan pendientes porque dependen de la capa de persistencia que se construirá más adelante.

## Restricción no negociable (aplica a TODAS las HU)

> **La estructura del JSON de salida (`status`, `timestamp`, `version`, `data.analysis_metadata`, `data.email_metadata`, `data.cabeceras_email`, `data.findings`) no debe cambiar de forma incompatible.** Los flujos de n8n dependen de estas rutas exactas. Cualquier campo nuevo se agrega como clave adicional (nunca se renombra ni se elimina una existente) y debe validarse contra el test de contrato de salida definido en HU-01.

## Definition of Done (DoD) — aplica a todas las HU

Una HU no se considera terminada hasta que cumpla **todo** lo siguiente:

1. Código implementado y revisado (self-review o par).
2. **Revisión de seguridad** específica de la HU (ver sección "Seguridad" de cada historia) — sin inyección, sin ReDoS, sin fugas de datos sensibles en logs, sin nuevas superficies de ataque sin mitigar.
3. **Probado en entorno virtual** (`venv`) local, no solo "funciona en mi máquina":
   ```bash
   python -m venv .venv
   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   pip install pytest bandit pip-audit  # dependencias de desarrollo/seguridad
   pytest
   bandit -r app.py
   pip-audit -r requirements.txt
   ```
4. El test de contrato de salida (HU-01) sigue en verde — ninguna clave existente fue renombrada/eliminada.
5. No se registran datos sensibles (API key, cuerpo completo del correo, adjuntos) en logs de nivel `INFO` o superior.
6. Documentación actualizada si el cambio introduce una nueva variable de entorno o archivo de configuración.
7. **Commit y push a `main`** en https://github.com/lemarunico2020/Heroku_PhishProtect con mensaje descriptivo que referencie el ID de la HU (ej. `HU-02: activar de-fanging de IOCs con ioc-fanger`). Solo se hace commit/push una vez cumplidos los puntos 1-6 — nunca se sube código sin tests ni revisión de seguridad pasados.
8. `status.md` actualizado (estado, fecha, hash/resumen del commit, siguiente HU) como último paso, después del push.

---

## Sprint 1 — Fundamentos y quick wins

**Objetivo:** blindar el contrato de salida antes de tocar nada, y entregar las mejoras de mayor valor con menor riesgo/costo.

### HU-01: Test de regresión del contrato de salida (golden JSON)

**Como** responsable de mantener la integración con n8n
**Quiero** una suite de pruebas que valide que la estructura del JSON de respuesta no cambia
**Para** poder iterar sobre el resto de las historias con la certeza de que ningún flujo de n8n se rompe.

**Criterios de aceptación:**
- Dado un archivo `.eml` y un `.msg` de prueba (sintéticos, sin datos reales de clientes), cuando se llama a `/api/v1/analyze_email`, entonces la respuesta contiene exactamente las claves esperadas en cada nivel del JSON (comparación de *esquema*, no de valores exactos, ya que timestamps/IDs cambian).
- El test falla si se elimina o renombra una clave existente en `data.email_metadata`, `data.cabeceras_email` o `data.findings`.
- El test **no** falla si se agrega una clave nueva (para no bloquear las siguientes HU).

**Tareas técnicas:**
- Crear `tests/fixtures/` con 2-3 correos `.eml`/`.msg` sintéticos (generados a mano, sin PII real).
- Crear `tests/test_output_contract.py` con `pytest` + Flask test client, validando el esquema (se puede usar `jsonschema` con `additionalProperties` permisivo en el nivel superior pero estricto en las claves obligatorias).
- Configurar `pytest` como dependencia de desarrollo (`requirements-dev.txt`).

**Seguridad:**
- Los fixtures de prueba deben ser correos **sintéticos**, nunca correos reales capturados de producción (evita fuga de PII/IOCs reales en el repositorio público de GitHub).
- Verificar que el test client no expone la API key real: usar una key de prueba vía variable de entorno `PHISHPROTECT_API_KEY` en el entorno de test, nunca hardcodeada en el repo.

**Pruebas en entorno virtual:**
```bash
pip install pytest jsonschema
pytest tests/test_output_contract.py -v
```

**Estimación:** 3 puntos

---

### HU-02: Activar de-fanging de IOCs con `ioc-fanger`

**Como** analista de seguridad
**Quiero** que la API detecte IOCs "defangueados" (`hxxp://`, `dominio[.]com`, `192[.]168[.]1[.]1`)
**Para** no perder indicadores que los atacantes ofuscan deliberadamente en el cuerpo del correo.

**Criterios de aceptación:**
- Dado un correo cuyo cuerpo contiene `hxxps://dominio-malo[.]com/payload`, cuando se analiza, entonces `data.findings.network_indicators.domains` y `.urls` contienen la versión "refanged" (`https://dominio-malo.com/payload`).
- El comportamiento actual con IOCs no defangueados no cambia (regresión cero, validado por HU-01).
- El contenido nunca se aumenta de tamaño más allá del límite ya definido por `MAX_CONTENT_ANALYSIS_SIZE`.

**Tareas técnicas:**
- Importar `ioc_fanger` en `app.py`.
- Aplicar `ioc_fanger.fang(...)`/`refang` sobre `analyzed_content` antes de pasarlo a `find_iocs_safe`, en `analyze_eml` y `analyze_msg`.
- Actualizar `README.md` mencionando el soporte de IOCs defangueados.

**Seguridad:**
- `ioc-fanger` opera con expresiones regulares sobre contenido no confiable (proveniente de un correo subido por cualquiera): aplicar el fanging **después** de truncar el contenido a `MAX_CONTENT_ANALYSIS_SIZE` (ya existe el límite), para evitar exponer una superficie de ReDoS sobre payloads arbitrariamente grandes.
- Fijar la versión de `ioc-fanger` en `requirements.txt` (ya está pineada) y correr `pip-audit` para descartar CVEs conocidos en la librería antes de habilitarla.

**Pruebas en entorno virtual:**
```bash
pip install -r requirements.txt
pytest tests/test_ioc_fanger.py -v
python -c "from ioc_fanger import fang; print(fang('hxxp://malo[.]com'))"
```

**Estimación:** 2 puntos

---

### HU-03: Allowlist configurable de dominios y correos

**Como** analista de seguridad
**Quiero** poder mantener una lista de dominios/correos propios o de confianza que nunca deben salir como IOC
**Para** reducir falsos positivos sin tener que tocar código cada vez que se agrega una excepción.

**Criterios de aceptación:**
- Dado un archivo `config/allowlist_domains.txt` con un dominio por línea (comentarios con `#`), cuando ese dominio aparece en el correo analizado, entonces no aparece en `data.findings.network_indicators.domains`.
- Igual para `config/allowlist_emails.txt` sobre `email_addresses`.
- Si los archivos no existen, la API sigue funcionando igual que hoy (allowlist vacía, sin errores).
- Agregar/quitar una línea del archivo y reiniciar el servicio refleja el cambio sin tocar código.

**Tareas técnicas:**
- Crear `config/allowlist_domains.txt` y `config/allowlist_emails.txt` (con ejemplos comentados) versionados en el repo.
- Función `load_allowlist(path)` que lee el archivo una vez al iniciar la app y lo cachea en un `set()` en memoria (normalizado a minúsculas).
- Extender `filter_recipient_iocs` (o agregar un paso adicional) para excluir también lo que esté en la allowlist, reutilizando la misma lógica de filtrado ya existente.
- Ruta del archivo configurable vía variable de entorno (`ALLOWLIST_DOMAINS_PATH`, `ALLOWLIST_EMAILS_PATH`) con default a `config/`.

**Seguridad:**
- La ruta del archivo de allowlist **debe** ser una ruta fija de configuración del servidor, nunca un valor tomado de la request del usuario — evita path traversal (`../../etc/passwd`) si en el futuro alguien intenta parametrizarlo desde la API.
- Validar que el archivo se abre en modo lectura y con manejo de excepciones (archivo corrupto/no UTF-8 no debe tumbar el servicio, solo loguear un warning y continuar con allowlist vacía).
- No hay `eval`/`exec` sobre el contenido del archivo: es texto plano, una línea = una entrada.

**Pruebas en entorno virtual:**
```bash
pip install -r requirements.txt
pytest tests/test_allowlist.py -v
# Prueba manual: agregar "midominio.com" a config/allowlist_domains.txt,
# analizar un correo que lo mencione y verificar que no aparece en el JSON.
```

**Estimación:** 3 puntos

---

### HU-04: Logging configurable por entorno y sin datos sensibles

**Como** operador del servicio
**Quiero** controlar el nivel de logging por variable de entorno y evitar que se registren datos sensibles
**Para** reducir el costo de I/O en producción a mayor volumen y evitar fugas de información (API key, cuerpo del correo) en los archivos de log.

**Criterios de aceptación:**
- Dado `LOG_LEVEL=INFO` en el entorno, cuando corre la app, entonces no se generan líneas de `DEBUG` (cabeceras completas, contenido decodificado) en `ioc_finder.log`.
- El valor por defecto si no se define `LOG_LEVEL` es `INFO` (no `DEBUG` como hoy).
- Ningún log de nivel `INFO` o superior contiene el valor de `API_KEY` ni el cuerpo completo del correo (`email_body`).

**Tareas técnicas:**
- Reemplazar `level=logging.DEBUG` por `level=os.environ.get('LOG_LEVEL', 'INFO')` en la configuración de `logging.basicConfig`.
- Revisar todos los `logger.info`/`logger.debug` que hoy imprimen contenido completo (p. ej. cabeceras completas en `extract_email_headers`) y bajarlos a `DEBUG` o truncarlos.
- Documentar `LOG_LEVEL` en `README.md`.

**Seguridad:**
- Auditoría explícita de todos los `logger.*` existentes en `app.py` para confirmar que ninguno imprime la API key en texto plano (hoy no lo hace, pero se deja como criterio de aceptación explícito para no introducirlo a futuro).
- Los logs con `exc_info=True` no deben incluir el contenido del archivo analizado en el traceback (verificar que las excepciones no interpolan el cuerpo del correo en el mensaje).

**Pruebas en entorno virtual:**
```bash
LOG_LEVEL=INFO python app.py
# Analizar un correo de prueba y revisar ioc_finder.log:
# no debe aparecer el cuerpo completo del correo ni la API key.
grep -i "api_key\|X-API-Key" ioc_finder.log  # no debe haber coincidencias con el valor real
```

**Estimación:** 2 puntos

---

## Sprint 2 — Enriquecimiento local de IOCs

**Objetivo:** sacar más valor de datos que ya se reciben, sin llamadas externas ni latencia relevante.

### HU-05: Extraer IP del primer salto en la cadena `Received`

**Como** analista de seguridad
**Quiero** un campo explícito con la IP de origen probable del correo
**Para** no tener que parsear manualmente el `received_chain` crudo en n8n.

**Criterios de aceptación:**
- Se agrega el campo `data.cabeceras_email.originating_ip_guess` (nuevo, aditivo) con la primera IP pública encontrada recorriendo `received_chain` de atrás hacia adelante, o `null` si no se encuentra ninguna.
- Los campos existentes de `cabeceras_email` no cambian.
- Funciona igual para EML y MSG.

**Tareas técnicas:**
- Función `guess_originating_ip(received_chain)` con regex de IPv4/IPv6 y exclusión de rangos privados/reservados (RFC1918, loopback) para evitar devolver IPs internas del propio servidor de correo.
- Integrarla en `build_analysis_result` como campo nuevo dentro de `cabeceras_email`.

**Seguridad:**
- Validar el formato de IP extraído con una librería estándar (`ipaddress` de la stdlib) antes de incluirlo en la respuesta, para no propagar strings arbitrarios mal formados como si fueran IOCs válidos.
- Limitar el número de líneas de `received_chain` procesadas (ya está acotado por el tamaño del correo) para evitar costos de regex en cadenas anómalamente largas.

**Pruebas en entorno virtual:**
```bash
pytest tests/test_originating_ip.py -v
```

**Estimación:** 3 puntos

---

### HU-06: Extracción de texto de adjuntos TXT/HTML para búsqueda de IOCs

**Como** analista de seguridad
**Quiero** que el contenido de texto de adjuntos `.txt`/`.html` también se analice en busca de IOCs
**Para** detectar URLs/dominios maliciosos ocultos en el adjunto y no solo en el cuerpo del correo.

**Criterios de aceptación:**
- Dado un adjunto `.html` que contiene una URL maliciosa, cuando se analiza el correo, entonces esa URL aparece en `data.findings.network_indicators.urls` (mismo campo existente, sin nuevas claves).
- Solo se procesan adjuntos de tipo texto/HTML y por debajo de `MAX_ATTACHMENT_SIZE` (reutiliza el límite ya existente).
- Adjuntos de otros tipos (binarios, ejecutables, PDFs) no se intentan decodificar como texto.

**Tareas técnicas:**
- Función `extract_attachment_text(filename, content_type, data)` que, si el `content_type` es `text/plain` o `text/html`, decodifica de forma segura (mismo patrón de múltiples encodings ya usado en `extract_body`) y para HTML extrae solo el texto visible (`BeautifulSoup(html, "html.parser").get_text()` — **sin** parser `lxml` para evitar XXE).
- El texto extraído se concatena a `analyzed_content` antes de `find_iocs_safe`, con límite de tamaño individual por adjunto.
- Agregar `beautifulsoup4` a `requirements.txt` (pineada a versión específica).

**Seguridad (crítico — se está parseando contenido no confiable subido por terceros):**
- Usar el parser `html.parser` (stdlib, sin soporte de entidades externas) en BeautifulSoup, **nunca** `lxml` sin sandboxear, para prevenir ataques tipo XXE/billion-laughs.
- **No renderizar** el HTML (nada de headless browser/Selenium): solo extracción de texto plano. Esto evita ejecución de JavaScript y cualquier intento de SSRF vía `<img src=...>` u otros recursos remotos.
- No seguir ni resolver ningún recurso externo referenciado en el HTML (nunca hacer un `requests.get` sobre URLs encontradas dentro del adjunto).
- Aplicar timeout/límite de tiempo de procesamiento por adjunto (p. ej. `signal.alarm` en Linux o un límite de tamaño más estricto en Windows) para mitigar adjuntos diseñados para causar consumo excesivo de CPU en el parseo.
- Reutilizar el límite `MAX_ATTACHMENT_SIZE` ya existente — no se procesan adjuntos más grandes que ese límite.

**Pruebas en entorno virtual:**
```bash
pip install beautifulsoup4
pytest tests/test_attachment_text_extraction.py -v
# Incluir un caso de prueba con un HTML "malicioso" sintético (XXE, script embebido)
# y verificar que no se ejecuta nada y que el análisis no cuelga ni crashea.
```

**Estimación:** 5 puntos

---

### HU-07 (stretch): Extracción de texto de adjuntos PDF

**Como** analista de seguridad
**Quiero** que también se analice el texto de adjuntos PDF
**Para** detectar IOCs en el tipo de adjunto más común en campañas de phishing dirigido.

**Criterios de aceptación:**
- Igual que HU-06 pero para `content_type == 'application/pdf'`, usando una librería de extracción de texto (no de renderizado).
- Si la extracción falla o tarda más de un umbral definido, el análisis del correo continúa sin bloquear (se registra el adjunto sin el texto extraído, no se cae la request).

**Tareas técnicas:**
- Evaluar `pypdf` (mantenida activamente, sin dependencias nativas pesadas) para extracción de texto.
- Aplicar el mismo pipeline de concatenación a `analyzed_content` que en HU-06.
- Definir un timeout explícito por adjunto (p. ej. 5 segundos) — si se excede, se omite el adjunto sin fallar la request completa.

**Seguridad (crítico):**
- Los parsers de PDF son una superficie de ataque histórica (decompression bombs, streams malformados que consumen memoria/CPU sin límite). Es obligatorio:
  - Timeout duro por adjunto.
  - Límite de páginas procesadas (p. ej. primeras 20 páginas).
  - Ejecutar la extracción en un bloque `try/except` amplio que nunca deje caer el request completo.
- Fijar la versión de la librería elegida y correr `pip-audit` antes de habilitarla — los parsers de PDF acumulan CVEs con frecuencia.
- No usar ninguna librería que dependa de binarios externos con historial de vulnerabilidades conocidas (evitar wrappers sobre Ghostscript, por ejemplo).

**Pruebas en entorno virtual:**
```bash
pip install pypdf
pytest tests/test_pdf_extraction.py -v
# Incluir un PDF sintético grande/anómalo para verificar que el timeout/límite funciona
# y que un PDF corrupto no rompe el análisis del correo completo.
```

**Estimación:** 5 puntos (marcada como *stretch*, se puede mover al Sprint 3 si el Sprint 2 se satura)

---

## Sprint 3 — Preparación para IA/Machine Learning

**Objetivo:** entregar un bloque de features derivadas, 100% local (sin llamadas externas), listo para consumir desde n8n o un futuro modelo, sin tocar la estructura existente.

### HU-08: Diseño del esquema `ml_features`

**Como** responsable de la futura integración de ML
**Quiero** un esquema claro y versionado del nuevo bloque `data.ml_features`
**Para** que el resto del equipo (y n8n) sepa exactamente qué campos esperar antes de que se implementen.

**Criterios de aceptación:**
- Documento (`docs/ml_features_schema.md`) con la lista de campos, tipo de dato y descripción, revisado antes de implementar HU-09/HU-10.
- El bloque se agrega como `data.ml_features` (nueva clave de primer nivel dentro de `data`), sin modificar `findings` ni `email_metadata`.
- Incluye un campo `ml_features_version` (string) para poder evolucionar el esquema sin romper consumidores.

**Tareas técnicas:**
- Definir campos iniciales: `url_count`, `domain_count`, `spf_result`, `dkim_result`, `dmarc_result`, `display_name_domain_mismatch` (bool), `subject_urgency_score`, `has_executable_attachment` (bool), `attachment_count`.
- Revisar el esquema con el equipo/usuario antes de codificar (evita retrabajo).

**Seguridad:**
- No incluye ningún dato crudo adicional del correo (no duplica PII); son valores derivados/numéricos/booleanos.

**Pruebas en entorno virtual:** N/A (historia de diseño/documentación), pero se valida que el `.md` quede versionado en el repo.

**Estimación:** 2 puntos

---

### HU-09: Features de autenticación y remitente

**Como** consumidor del bloque `ml_features` (n8n o un futuro modelo)
**Quiero** features derivadas de SPF/DKIM/DMARC y de posibles suplantaciones del remitente
**Para** poder priorizar/puntuar correos sospechosos sin lógica adicional en n8n.

**Criterios de aceptación:**
- `data.ml_features.spf_result`, `.dkim_result`, `.dmarc_result` reflejan lo mismo que ya existe en `email_metadata.authentication` (mismo valor, formato apto para ML — p. ej. normalizado a minúsculas o one-hot si se define así en HU-08).
- `data.ml_features.display_name_domain_mismatch` es `true` cuando el nombre para mostrar del remitente sugiere una organización distinta al dominio real del `From` (heurística simple, ej. comparar contra la allowlist de HU-03 o contra patrones conocidos).

**Tareas técnicas:**
- Función `compute_sender_features(msg_from_header, auth_results)`.
- Reutilizar los resultados ya calculados por `parse_authentication_results`/`parse_msg_authentication` (no se vuelve a parsear nada).

**Seguridad:**
- Todo el cálculo es sobre datos ya parseados de forma segura en pasos previos; no se introduce ninguna nueva fuente de entrada no confiable.
- Las heurísticas de comparación de strings deben tener límite de longitud para evitar costos de comparación excesivos en headers anómalamente largos (ya limitado por el tamaño máximo de correo).

**Pruebas en entorno virtual:**
```bash
pytest tests/test_ml_features_sender.py -v
```

**Estimación:** 3 puntos

---

### HU-10: Features de contenido (urgencia, conteos, adjuntos ejecutables)

**Como** consumidor del bloque `ml_features`
**Quiero** features derivadas del cuerpo del correo y de los adjuntos
**Para** contar con señales típicas de phishing (urgencia, cantidad de enlaces, adjuntos ejecutables) listas para un modelo.

**Criterios de aceptación:**
- `data.ml_features.url_count` y `.domain_count` coinciden con el tamaño de las listas ya presentes en `findings.network_indicators`.
- `data.ml_features.subject_urgency_score` es un entero/float basado en coincidencias contra una lista **configurable** de palabras clave de urgencia (ej. `config/urgency_keywords.txt`, mismo patrón que la allowlist de HU-03).
- `data.ml_features.has_executable_attachment` es `true` si algún adjunto tiene extensión de una lista conocida (`.exe`, `.scr`, `.js`, `.vbs`, `.bat`, etc., también configurable).

**Tareas técnicas:**
- Función `compute_content_features(structured_iocs, attachments, subject, body)`.
- Archivo `config/urgency_keywords.txt` y `config/executable_extensions.txt` versionados con valores por defecto razonables.
- Reutilizar el mecanismo de carga de listas en memoria ya creado en HU-03 (una sola función genérica `load_text_list(path)` compartida).

**Seguridad:**
- El matching de palabras clave debe usar comparación simple de substrings o regex acotadas (evitar patrones regex complejos que puedan causar ReDoS sobre `subject`/`body` de tamaño no trivial).
- La lista de extensiones ejecutables se compara solo contra el string del nombre de archivo ya extraído (dato ya validado en pasos previos), sin ejecutar ni abrir el adjunto.

**Pruebas en entorno virtual:**
```bash
pytest tests/test_ml_features_content.py -v
```

**Estimación:** 3 puntos

---

## Sprint 4 — Rendimiento, mantenibilidad y despliegue en Docker/EasyPanel

**Objetivo:** preparar el servicio para mayor volumen y para el despliegue en Docker sobre EasyPanel, y reducir riesgo de regresiones futuras.

### HU-11: Tuning de gunicorn y límites de recursos

**Como** operador del servicio
**Quiero** una configuración de gunicorn ajustada (workers, threads, timeout) vía variables de entorno
**Para** soportar mayor volumen concurrente sin agotar recursos ni exponerse a solicitudes colgadas.

**Criterios de aceptación:**
- El comando de arranque permite configurar `WEB_CONCURRENCY` (workers) y `GUNICORN_THREADS` sin modificar código.
- Se define un `--timeout` explícito en gunicorn para evitar que una request colgada bloquee un worker indefinidamente.
- Documentado en `README.md` con valores recomendados según CPU disponible.

**Tareas técnicas:**
- Actualizar `Procfile`/comando de Docker a algo como:
  `gunicorn -w ${WEB_CONCURRENCY:-2} --threads ${GUNICORN_THREADS:-2} -k gthread --timeout ${GUNICORN_TIMEOUT:-60} app:app`
- Documentar recomendaciones de dimensionamiento.

**Seguridad:**
- El `--timeout` explícito es en sí mismo una mitigación de disponibilidad (evita que uploads/parseos maliciosamente lentos agoten todos los workers — un tipo de DoS de bajo esfuerzo).
- Confirmar que `MAX_FILE_SIZE` sigue aplicando también a nivel de proxy/EasyPanel si este impone límites de tamaño de body (evitar que una request enorme llegue completa a gunicorn antes de ser rechazada).

**Pruebas en entorno virtual:**
```bash
gunicorn -w 2 --threads 2 -k gthread --timeout 60 app:app
# Prueba de carga simple con múltiples uploads concurrentes (ej. usando `hey` o `ab`)
```

**Estimación:** 2 puntos

---

### HU-12: Refactor de `app.py` en módulos + endurecimiento de la comparación de API Key

**Como** desarrollador del proyecto
**Quiero** separar `app.py` en módulos (`parsers/`, `iocs.py`, `routes.py`, `auth.py`, `config.py`) y corregir la comparación de la API Key
**Para** reducir el riesgo de romper algo al seguir agregando funcionalidades, y cerrar una vulnerabilidad de timing attack en la autenticación.

**Criterios de aceptación:**
- El comportamiento de cada endpoint es idéntico al actual (validado por HU-01 y por los tests de cada HU anterior, que deben seguir en verde tras el refactor).
- La comparación `request_api_key != API_KEY` se reemplaza por una comparación de tiempo constante (`hmac.compare_digest`).
- La estructura de carpetas queda documentada en `README.md`.

**Tareas técnicas:**
- Extraer a módulos: `parsers/eml.py`, `parsers/msg.py`, `iocs.py` (find/filter/structure), `auth.py` (decorador `require_api_key` con `hmac.compare_digest`), `config.py` (todas las variables de entorno/límites), `routes.py` o blueprints de Flask.
- `app.py` queda como punto de entrada mínimo que registra el blueprint y arranca la app.
- Ejecutar toda la suite de tests de los sprints anteriores tras el refactor (es net-zero en funcionalidad, no debería fallar nada).

**Seguridad:**
- **Corrección de vulnerabilidad real detectada:** la comparación actual de API Key (`!=` sobre strings) es vulnerable a *timing attacks* (permite inferir la key carácter a carácter midiendo tiempos de respuesta). Se reemplaza por `hmac.compare_digest(request_api_key, API_KEY)`.
- Revisar que ninguna variable sensible (`API_KEY`) quede expuesta en logs o en mensajes de error durante el refactor.
- Ejecutar `bandit -r .` sobre todo el proyecto tras el refactor como parte del checklist de la HU.

**Pruebas en entorno virtual:**
```bash
pytest -v  # toda la suite acumulada de sprints 1-3 debe seguir pasando
bandit -r .
```

**Estimación:** 5 puntos

---

### HU-13: Dockerfile y despliegue en EasyPanel

**Como** operador del servicio
**Quiero** una imagen Docker productiva del proyecto
**Para** poder desplegarlo en EasyPanel en lugar de (o además de) Heroku.

**Criterios de aceptación:**
- `docker build .` produce una imagen funcional que expone el mismo comportamiento que hoy en Heroku.
- El contenedor corre como usuario no-root.
- Las variables de entorno (`PHISHPROTECT_API_KEY`, `MAX_FILE_SIZE_MB`, `LOG_LEVEL`, etc.) se inyectan en tiempo de ejecución, nunca hardcodeadas en la imagen.
- `docker-compose.yml` (opcional) para levantar el servicio localmente en un solo comando.

**Tareas técnicas:**
- `Dockerfile` basado en `python:3.9-slim` (o la versión que finalmente se use), instalando `requirements.txt`, copiando el código, exponiendo el puerto vía `$PORT`, arrancando con el mismo comando de gunicorn de HU-11.
- `USER` no-root explícito.
- `.dockerignore` (excluir `.venv/`, `ioc_finder.log`, `tests/`, `.git/`, etc.).
- Documentar en `README.md` el paso a paso de despliegue en EasyPanel (variables de entorno requeridas, puerto, healthcheck).

**Seguridad:**
- Imagen base `slim` (superficie mínima) y versión de Python pineada explícitamente (evitar `latest`).
- Usuario no-root dentro del contenedor (mitiga impacto de una eventual RCE dentro del proceso).
- Ningún secreto (`API_KEY`) incluido en el `Dockerfile` ni en la imagen — solo via variables de entorno inyectadas por EasyPanel en runtime.
- `.dockerignore` evita que archivos de log, `.git/` o el propio `.env` local terminen dentro de la imagen.
- Si EasyPanel expone un healthcheck HTTP, usar una ruta que **no** requiera API Key para no filtrarla en configuración de infraestructura (o documentar claramente que `/api/v1/check_auth` la requiere y no debe usarse como healthcheck público).

**Pruebas en entorno virtual:**
```bash
docker build -t phishprotect:test .
docker run -e PHISHPROTECT_API_KEY=test-key -p 5001:5001 phishprotect:test
curl -X POST -F "email_file=@tests/fixtures/sample.eml" -H "X-API-Key: test-key" http://localhost:5001/api/v1/analyze_email
```

**Estimación:** 5 puntos

---

## Resumen de sprints

| Sprint | Enfoque | HU incluidas | Puntos estimados |
|---|---|---|---|
| Sprint 1 | Fundamentos + quick wins | HU-01 a HU-04 | 10 |
| Sprint 2 | Enriquecimiento local de IOCs | HU-05, HU-06, (HU-07 stretch) | 8 (+5 stretch) |
| Sprint 3 | Preparación IA/ML | HU-08 a HU-10 | 8 |
| Sprint 4 | Rendimiento + Docker/EasyPanel | HU-11 a HU-13 | 12 |
| **Total** | | **13 HU** | **~38-43 puntos** |

## Backlog futuro (no incluido en estos sprints)

- **Persistencia de resultados en base de datos** — a cargo del usuario, se integrará posteriormente.
- **Enriquecimiento externo** (VirusTotal, AbuseIPDB, WHOIS) — depende de una cola asíncrona y probablemente de la capa de persistencia; retomar cuando esas piezas existan.
- **Cola asíncrona (Celery/RQ + Redis)** — solo si el volumen de correos lo justifica; cambia el contrato de interacción con n8n y requiere diseño aparte.
- **CI/CD con pipeline de seguridad automatizado** (bandit + pip-audit + pytest en cada PR vía GitHub Actions) — buen candidato para un Sprint 5 una vez estabilizado lo anterior.
