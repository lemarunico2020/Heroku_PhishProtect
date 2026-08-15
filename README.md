# PhishProtect API

PhishProtect es una API de análisis de correos electrónicos que extrae indicadores de compromiso (IOCs) de archivos EML y MSG para ayudar en la identificación y análisis rápido de posibles amenazas de phishing.

## Descripción

PhishProtect ofrece un servicio completo para el análisis forense de correos electrónicos sospechosos, permitiendo a los analistas de seguridad identificar rápidamente posibles amenazas. La API procesa archivos EML y MSG y extrae automáticamente diversos indicadores de compromiso, como:

- **Indicadores de red**: Dominios, direcciones IP, URLs y direcciones de correo electrónico
- **Indicadores de archivo**: Hashes (MD5, SHA1, SHA256, SHA512) y rutas de archivos

El servicio está diseñado para integrarse fácilmente en flujos de trabajo de respuesta a incidentes y soluciones SOAR (Security Orchestration, Automation and Response).

## Características

- ✅ **Análisis de archivos EML y MSG**: Procesa correos electrónicos en formato EML y MSG (Microsoft Outlook).
- ✅ **Extracción de IOCs**: Identifica automáticamente indicadores de compromiso.
- ✅ **Procesamiento robusto**: Maneja múltiples codificaciones y formatos de email.
- ✅ **Filtrado inteligente**: Elimina falsos positivos como direcciones de destinatarios.
- ✅ **Resultados estructurados**: Proporciona datos en formato JSON para fácil integración.
- ✅ **API RESTful**: Integración sencilla con otras herramientas y plataformas.
- ✅ **Análisis de adjuntos**: Extrae y calcula hashes de archivos adjuntos.
- ✅ **Detección automática de formato**: Detecta si el archivo es EML o MSG aunque no tenga la extensión correcta.
- ✅ **Soporte de IOCs defangueados**: Reconoce indicadores ofuscados manualmente (`hxxp://`, `dominio[.]com`, `actor[at]dominio.com`) y los normaliza antes de extraerlos.
- ✅ **Allowlist configurable**: Dominios y correos propios o de confianza definidos en `config/allowlist_domains.txt` y `config/allowlist_emails.txt` nunca se reportan como IOC.
- ✅ **IP de origen probable**: `data.cabeceras_email.originating_ip_guess` expone la primera IP pública encontrada recorriendo la cadena `Received` desde el salto más cercano al origen, excluyendo rangos privados/reservados/loopback/multicast.
- ✅ **Búsqueda de IOCs en adjuntos de texto**: el texto visible de adjuntos `.txt`/`.html` (por debajo del límite de tamaño de adjunto) también se analiza en busca de IOCs. El HTML se procesa solo con `html.parser` (sin renderizar, sin resolver recursos externos) para extraer texto visible de forma segura.
- ✅ **Búsqueda de IOCs en adjuntos PDF**: el texto de adjuntos `.pdf` (primeras 20 páginas, con timeout de 5s por adjunto en plataformas Unix) también se analiza en busca de IOCs. Un PDF corrupto o que exceda el timeout no interrumpe el análisis del correo.

## Requisitos

- Python 3.9+
- Flask 3.1.0+
- IOC Finder 7.3.0+
- Python-dateutil
- Email-validator
- Extract-msg (para archivos MSG)
- BeautifulSoup4 (para extracción de texto de adjuntos HTML)
- Pypdf (para extracción de texto de adjuntos PDF)
- Gunicorn (para producción)

## Instalación y Despliegue

### Opción 1: Despliegue en Heroku (Recomendado)

1. Haz clic en el botón "Deploy to Heroku" arriba
2. Regístrate o inicia sesión en Heroku
3. Configura el nombre de tu aplicación
4. Haz clic en "Deploy app"

### Opción 2: Docker / EasyPanel

Requiere Docker. `docker build .` produce una imagen productiva (usuario no-root, basada en `python:3.12-slim`) que expone el mismo comportamiento que en Heroku.

**Local, con Docker directamente:**

```bash
docker build -t phishprotect:test .
docker run -e PHISHPROTECT_API_KEY=tu-api-key -p 5001:5001 phishprotect:test
curl -X POST -F "email_file=@tests/fixtures/sample_phishing.eml" -H "X-API-Key: tu-api-key" http://localhost:5001/api/v1/analyze_email
```

**Local, con `docker-compose.yml` (un solo comando):**

```bash
PHISHPROTECT_API_KEY=tu-api-key docker compose up --build
```

**En EasyPanel:**

1. Crear un nuevo servicio de tipo "App" apuntando a este repositorio (EasyPanel detecta el `Dockerfile` automáticamente) o subir la imagen ya construida a un registro.
2. Configurar las variables de entorno requeridas (ver tabla abajo) — **nunca** se hardcodean en el `Dockerfile` ni en la imagen, se inyectan en tiempo de ejecución.
3. Configurar el puerto expuesto: el contenedor escucha en `$PORT` (por defecto `5001` si no se define).
4. Si EasyPanel pide una ruta de healthcheck HTTP, usar `/` (no requiere API Key). El Dockerfile ya incluye un `HEALTHCHECK` propio sobre esa misma ruta. **Nunca** usar `/api/v1/check_auth` como healthcheck público: exige la API Key real y la expondría en la configuración de infraestructura.

| Variable | Requerida | Descripción | Valor por defecto |
|---|---|---|---|
| `PHISHPROTECT_API_KEY` | Sí | API Key que deben presentar los clientes | *(ninguno — sin definirla, la app arranca con una key de desarrollo insegura y lo advierte en el log)* |
| `PORT` | No | Puerto en el que escucha gunicorn dentro del contenedor | `5001` |
| `LOG_LEVEL` | No | Nivel de logging (`DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`) | `INFO` |
| `MAX_FILE_SIZE_MB` / `MAX_CONTENT_SIZE_MB` / `MAX_ATTACHMENT_SIZE_MB` | No | Límites de tamaño (ver sección Requisitos) | `18` / `2` / `10` |
| `ALLOWLIST_DOMAINS_PATH` / `ALLOWLIST_EMAILS_PATH` | No | Rutas a los archivos de allowlist | `config/allowlist_domains.txt` / `config/allowlist_emails.txt` |
| `WEB_CONCURRENCY` / `GUNICORN_THREADS` / `GUNICORN_TIMEOUT` | No | Tuning de gunicorn (ver sección "Configuración de gunicorn") | `2` / `2` / `60` |

El `.dockerignore` excluye del build todo lo que no hace falta en runtime (`.git/`, `tests/`, `docs/`, logs, entornos virtuales, `.env` local, etc.); el directorio `config/` sí se incluye porque de ahí se leen los archivos de allowlist.

### Opción 3: Instalación Local

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/phishprotect.git
cd phishprotect

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la aplicación
python app.py
```

## Estructura del proyecto

Desde HU-12, el código está organizado en módulos según responsabilidad (antes vivía todo en un único `app.py`):

```
app.py               # Punto de entrada: crea la app Flask y registra el blueprint de rutas
settings.py           # Configuración: logging, API Key, límites de tamaño, allowlist
responses.py          # Helpers de formato de respuesta HTTP/JSON
auth.py               # Decorador require_api_key (hmac.compare_digest)
iocs.py                # Búsqueda/filtrado/estructuración de IOCs y ensamblado del resultado final
routes.py             # Endpoints Flask (Blueprint)
parsers/
  eml.py               # Parseo y análisis de archivos EML
  msg.py               # Parseo y análisis de archivos MSG (Outlook)
  attachments.py        # Extracción de texto de adjuntos TXT/HTML/PDF (compartido entre eml.py y msg.py)
config/                # Archivos de configuración en texto plano (allowlist_domains.txt, allowlist_emails.txt) — NO es un paquete Python
tests/                 # Suite de pytest
Dockerfile              # Imagen productiva (HU-13)
.dockerignore
docker-compose.yml     # Opcional, para levantar el servicio localmente en un solo comando
```

**Nota de nombres:** el módulo de configuración se llama `settings.py` y no `config.py` para evitar la colisión con el directorio `config/` ya existente (los archivos de texto plano de la allowlist de HU-03). Python resuelve esa colisión de forma determinista, pero es una fuente de confusión evitable.

## Uso

### Endpoint API

La API ofrece un endpoint principal para el análisis de archivos EML:

POST /api/v1/analyze_email

Este endpoint detectará automáticamente si el archivo es EML o MSG y lo procesará adecuadamente.

#### Ejemplo de solicitud con cURL:

# Usando el endpoint unificado
curl -X POST -F "email_file=@correo_sospechoso.eml" -H "X-API-Key: tu-api-key" https://tu-app.herokuapp.com/api/v1/analyze_email

#### Ejemplo de respuesta:

{
  "status": "success",
  "timestamp": "2025-03-03T12:34:56.789012",
  "version": "1.1",
  "data": {
    "analysis_metadata": {
      "analysis_id": "IOC-20250303-123456-789",
      "analysis_timestamp": "2025-03-03T12:34:56.789012",
      "file_analyzed": "correo_sospechoso.eml",
      "file_type": "eml"
    },
    "email_metadata": {
      "from": "remitente@dominio-sospechoso.com",
      "to": "destinatario@empresa.com",
      "subject": "Actualización de seguridad urgente",
      "date": "2025-03-02T10:15:30",
      "body_extracted": true,
      "body": "Contenido del correo...",
  },
    "findings": {
      "network_indicators": {
        "domains": ["dominio-malicioso.com", "servidor-c2.net"],
        "ipv4": ["192.168.1.1", "10.0.0.1"],
        "urls": ["https://dominio-malicioso.com/payload.php"],
        "email_addresses": ["actor-malicioso@dominio-sospechoso.com"]
      },
      "file_indicators": {
        "md5_hashes": ["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"],
        "sha256_hashes": ["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6..."]
      },
      "system_indicators": {
        "registry_keys": ["HKEY_LOCAL_MACHINE\\Software\\Malware"]
      }
    }
  }
}

## Interfaz Web

La aplicación también incluye una interfaz web básica para probar la API directamente desde el navegador:

Accede a tu aplicación en https://tu-app.herokuapp.com/
Selecciona un archivo EML o MSG
Haz clic en "Analizar"
Visualiza los resultados formateados

## Formatos soportados

La API soporta los siguientes formatos de correo electrónico:

- EML: Formato estándar de correo electrónico
- MSG: Formato de Microsoft Outlook

## Logging

El nivel de logging es configurable vía la variable de entorno `LOG_LEVEL` (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Por defecto es `INFO` (antes era `DEBUG` de forma fija), para no volcar en `ioc_finder.log` cabeceras completas ni contenido decodificado en producción. Un valor no reconocido cae a `INFO` sin interrumpir el arranque del servicio.

Ningún log de nivel `INFO` o superior contiene el valor de la API Key ni el cuerpo completo del correo analizado.

```bash
LOG_LEVEL=DEBUG python app.py  # diagnóstico puntual con detalle completo
```

## Allowlist de dominios y correos de confianza

Para reducir falsos positivos, la API excluye de los IOCs cualquier dominio o correo presente en:

- `config/allowlist_domains.txt` — un dominio por línea
- `config/allowlist_emails.txt` — un correo por línea

Ambos archivos admiten comentarios con `#` y líneas vacías. Se cargan una única vez al iniciar el servicio (reiniciar la app para reflejar cambios). Si no existen, la API funciona igual que hoy (allowlist vacía, sin errores).

Las rutas son configurables vía variables de entorno:

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `ALLOWLIST_DOMAINS_PATH` | Ruta al archivo de dominios permitidos | `config/allowlist_domains.txt` |
| `ALLOWLIST_EMAILS_PATH` | Ruta al archivo de correos permitidos | `config/allowlist_emails.txt` |

## Configuración de gunicorn (producción)

El comando de arranque en producción (`Procfile`) es configurable vía variables de entorno, sin tocar código:

```
web: gunicorn -w ${WEB_CONCURRENCY:-2} --threads ${GUNICORN_THREADS:-2} -k gthread --timeout ${GUNICORN_TIMEOUT:-60} app:app
```

| Variable | Descripción | Valor por defecto |
|---|---|---|
| `WEB_CONCURRENCY` | Número de workers (procesos) de gunicorn | `2` |
| `GUNICORN_THREADS` | Threads por worker (worker tipo `gthread`) | `2` |
| `GUNICORN_TIMEOUT` | Segundos antes de reciclar un worker con una request colgada | `60` |

**Valores recomendados según CPU disponible:** cada worker es un proceso Python completo (memoria propia); cada thread comparte esa memoria. El análisis de EML/MSG es mayormente I/O-bound (lectura del archivo, parseo de MIME/HTML/PDF) con picos cortos de CPU (hashing, regex de IOCs), por lo que conviene priorizar threads sobre workers frente al clásico `2×núcleos+1` de gunicorn (pensado para un solo hilo por worker):

- `WEB_CONCURRENCY` ≈ número de núcleos disponibles (ajustar a la baja si la memoria es el límite).
- `GUNICORN_THREADS` entre 2 y 4.
- `GUNICORN_TIMEOUT` en 60 (o más, si se esperan archivos grandes/lentos de analizar) — nunca `0` (deshabilita el timeout y permite que una request colgada bloquee un worker indefinidamente).

El `--timeout` explícito es en sí mismo una mitigación de disponibilidad: sin él, una solicitud diseñada para colgarse (o un archivo anómalamente lento de parsear) podría agotar todos los workers. Si se despliega detrás de un proxy (EasyPanel, un load balancer, etc.) que imponga su propio límite de tamaño de body, confirmar que sea igual o menor a `MAX_FILE_SIZE_MB` para que una solicitud excesivamente grande se rechace antes de llegar a gunicorn.

## Seguridad

Este servicio está diseñado para análisis de seguridad. Ten en cuenta:

- No procesa el contenido de archivos adjuntos potencialmente maliciosos.
- No ejecuta código contenido en los correos electrónicos.
- Elimina los archivos temporales después del análisis.
- Implementa logs detallados para auditoría.

### Riesgos de dependencias aceptados

- **`d8s-lists==0.8.0`** aparece en `pip-audit` bajo el advisory `PYSEC-2022-43027`, sin versión corregida disponible (el advisory cubre todas las versiones publicadas, sin un evento de "fixed" registrado). El backdoor real que originó el advisory estaba en una dependencia con otro nombre, `democritus-dicts` v0.1.0 (el proyecto completo se renombró de `democritus-*` a `d8s-*` tras el incidente). Se verificó que **ningún paquete `democritus-*` está presente** en el árbol de dependencias instalado, y que `d8s-lists` depende de `d8s-dicts` (el paquete renombrado, no el comprometido). Se acepta como riesgo residual, revisado el 2026-08-13; se re-evalúa si `ioc-finder` deja de depender de `d8s-lists` en una futura versión.

## Contribuir

Las contribuciones son bienvenidas. Para contribuir:

1. Haz un fork del repositorio
2. Crea una nueva rama (`git checkout -b feature/nueva-caracteristica`)
3. Realiza tus cambios
4. Ejecuta las pruebas
5. Haz commit de tus cambios (`git commit -am 'Añadir nueva característica'`)
6. Haz push a la rama (`git push origin feature/nueva-caracteristica`)
7. Crea un nuevo Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Para preguntas o soporte, por favor abre un issue en este repositorio.
