"""
Configuracion centralizada: logging, API Key, limites de tamano y
allowlist. Todo lo que hoy se lee de variables de entorno vive aca
(HU-12).

Nota de nombres: el modulo se llama settings.py y no config.py (aunque
la HU-12 sugiere ese nombre) para evitar la colision con el directorio
config/ ya existente en el repo (contiene los archivos de texto plano
de la allowlist de HU-03, config/allowlist_domains.txt y
config/allowlist_emails.txt). Python resuelve esa colision de forma
determinista (un modulo config.py le ganaria al paquete de namespace
config/), pero es una fuente de confusion innecesaria para quien lea
el codigo, asi que se evita directamente.
"""
import os
import logging
from logging.handlers import RotatingFileHandler

# Configurar logging. Nivel por defecto INFO (no DEBUG) para no volcar
# cabeceras completas ni contenido decodificado en producción; configurable
# vía LOG_LEVEL para habilitar DEBUG puntualmente en diagnóstico.
VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}

def resolve_log_level(raw_value):
    """
    Valida y normaliza el valor de LOG_LEVEL. Si esta ausente o no es uno
    de los niveles reconocidos por logging, cae a INFO en vez de fallar
    el arranque del servicio.
    """
    normalized = (raw_value or 'INFO').upper()
    return normalized if normalized in VALID_LOG_LEVELS else 'INFO'

_raw_log_level = os.environ.get('LOG_LEVEL', 'INFO')
LOG_LEVEL = resolve_log_level(_raw_log_level)

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'ioc_finder.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

if _raw_log_level.upper() not in VALID_LOG_LEVELS:
    logger.warning(f"LOG_LEVEL inválido: '{_raw_log_level}', usando INFO por defecto")

# Obtener la API Key de las variables de entorno (con fallback para desarrollo)
API_KEY = os.environ.get('PHISHPROTECT_API_KEY', 'mi-api-key-de-prueba')

if API_KEY == 'mi-api-key-de-prueba':
    logger.warning("Usando API Key de desarrollo. Configure PHISHPROTECT_API_KEY en producción.")

# Obtener límites de tamaño de las variables de entorno
MAX_FILE_SIZE_MB = int(os.environ.get('MAX_FILE_SIZE_MB', 18))
MAX_CONTENT_SIZE_MB = int(os.environ.get('MAX_CONTENT_SIZE_MB', 2))
MAX_ATTACHMENT_SIZE_MB = int(os.environ.get('MAX_ATTACHMENT_SIZE_MB', 10))

# Configuración de límites de tamaño (en bytes)
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_CONTENT_ANALYSIS_SIZE = MAX_CONTENT_SIZE_MB * 1024 * 1024
MAX_ATTACHMENT_SIZE = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024

logger.info(f"Límites configurados: Archivo máx: {MAX_FILE_SIZE_MB}MB, Contenido máx: {MAX_CONTENT_SIZE_MB}MB, Adjunto máx: {MAX_ATTACHMENT_SIZE_MB}MB")

# Rutas de la allowlist configurable de dominios y correos de confianza.
# Rutas fijas de configuracion del servidor (nunca tomadas de la request),
# para evitar path traversal si en el futuro se parametrizan desde la API.
ALLOWLIST_DOMAINS_PATH = os.environ.get('ALLOWLIST_DOMAINS_PATH', os.path.join('config', 'allowlist_domains.txt'))
ALLOWLIST_EMAILS_PATH = os.environ.get('ALLOWLIST_EMAILS_PATH', os.path.join('config', 'allowlist_emails.txt'))

def load_allowlist(path):
    """
    Carga un archivo de texto plano (una entrada por linea, comentarios con #)
    en un set() normalizado a minusculas. Si el archivo no existe o no se
    puede leer (encoding invalido, permisos, etc.), retorna un set() vacio
    y deja el servicio funcionando con la allowlist vacia en vez de tumbarlo.
    """
    entries = set()
    if not os.path.exists(path):
        logger.info(f"Archivo de allowlist no encontrado en '{path}', se usa allowlist vacía")
        return entries
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                entries.add(line.lower())
    except Exception as e:
        logger.warning(f"No se pudo leer la allowlist desde '{path}', se usa allowlist vacía: {str(e)}")
        return set()
    logger.info(f"Allowlist cargada desde '{path}': {len(entries)} entrada(s)")
    return entries

ALLOWLIST_DOMAINS = load_allowlist(ALLOWLIST_DOMAINS_PATH)
ALLOWLIST_EMAILS = load_allowlist(ALLOWLIST_EMAILS_PATH)
