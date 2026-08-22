"""
Enriquecimiento WHOIS del dominio remitente: fecha de creacion, registrador,
pais y dnssec, cuando estan disponibles. Modulo aislado del resto del
pipeline de analisis (find_iocs/d8s no se tocan): cualquier fallo (timeout,
TLD desconocido, dominio no encontrado, error de red) se traduce en
whois_ok=False con el resto de los campos en None. Nunca se propaga una
excepcion hacia build_analysis_result().

Usa python-whois (import `whois`), que consulta WHOIS por socket (puerto
43) directamente -sin depender del binario `whois` del sistema, que puede
no estar presente en el contenedor Docker-.

Para dominios de la familia .co (incluye .com.co, .edu.co, .gov.co, etc.,
todos registros de segundo nivel bajo el mismo TLD .co) se agrega un
fallback: si python-whois no devuelve fecha de creacion, se consulta
directamente por socket al servidor WHOIS autoritativo del registro .co.

Nota sobre el servidor WHOIS de .co: la guia "whois.nic.co" que circula en
varios tutoriales NO EXISTE (NXDOMAIN). El servidor autoritativo real,
confirmado consultando `whois.iana.org` (registro IANA del TLD .co) el
2026-08-22, es `whois.registry.co` (operado por CentralNic para el
Ministerio TIC de Colombia).
"""
import logging
import re
import socket
import time
from datetime import datetime

try:
    import whois as _python_whois
except ImportError:  # pragma: no cover - solo si la dependencia no esta instalada
    _python_whois = None

logger = logging.getLogger(__name__)

# Timeout corto por consulta WHOIS (cada intento individual, ya sea via
# python-whois o el fallback crudo).
WHOIS_TIMEOUT_SECONDS = 5

# Cantidad de intentos para la consulta primaria (python-whois). Se
# observaron fallos intermitentes de resolucion/conexion incluso contra
# TLDs tan comunes como .com; un segundo intento resuelve la mayoria.
_PYTHON_WHOIS_ATTEMPTS = 2

# Cache en memoria por dominio registrable, para no repetir consultas ni
# ser bloqueado por rate-limit del registro. TTL de 24 horas.
_CACHE_TTL_SECONDS = 24 * 60 * 60
_cache = {}

# Sufijos colombianos de segundo nivel bajo .co: el dominio registrable
# incluye esas dos etiquetas mas la que las precede (3 etiquetas en total).
# Ej.: "sea.chrysalis.com.co" -> "chrysalis.com.co".
_CO_SECOND_LEVEL_SUFFIXES = {
    "com.co", "edu.co", "gov.co", "net.co", "org.co", "mil.co", "nom.co",
}

# Servidor WHOIS autoritativo del registro .co, usado como fallback para
# toda la familia .co (incluye .com.co, .edu.co, etc. -son registros de
# segundo nivel bajo el mismo TLD .co, servidos por el mismo WHOIS-).
_CO_REGISTRY_WHOIS_SERVER = "whois.registry.co"

_RAW_FIELD_PATTERNS = {
    "creation_date": re.compile(
        r"(?im)^\s*(?:creation date|created(?: on)?|domain registration date)\s*:\s*(.+)$"
    ),
    "registrar": re.compile(r"(?im)^\s*registrar\s*:\s*(.+)$"),
    "country": re.compile(r"(?im)^\s*(?:registrant\s+)?country\s*:\s*(.+)$"),
    "dnssec": re.compile(r"(?im)^\s*dnssec\s*:\s*(.+)$"),
}

_DATE_IN_STRING_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")

_EMPTY_RESULT = {
    "fecha_creacion_dominio": None,
    "dominio_registrado_en": None,
    "pais": None,
    "dnssec": None,
    "whois_ok": False,
}


def extract_registrable_domain(from_header):
    """
    Extrae el dominio registrable de un header From. Soporta los formatos
    "Nombre <user@dominio.com>", "user@dominio.com" y "dominio.com" a
    secas. Consciente de sufijos colombianos de segundo nivel (ver
    _CO_SECOND_LEVEL_SUFFIXES): para esos, el registrable son las ultimas
    3 etiquetas; para el resto (incluido .co a secas), las ultimas 2.

    Devuelve None si no hay nada razonable que extraer.
    """
    if not from_header or not isinstance(from_header, str):
        return None

    match = re.search(r"<([^>]+)>", from_header)
    address = match.group(1) if match else from_header.strip()

    domain = address.rsplit("@", 1)[-1] if "@" in address else address

    domain = domain.strip().strip(".").lower()
    domain = domain.split("/")[0].split(":")[0].split("?")[0]

    if not domain or "." not in domain:
        return None

    labels = [label for label in domain.split(".") if label]
    if len(labels) < 2:
        return None

    last_two = ".".join(labels[-2:])
    if last_two in _CO_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])

    return last_two


def lookup_domain_info(registrable_domain):
    """
    Devuelve un dict con fecha_creacion_dominio/dominio_registrado_en/
    pais/dnssec/whois_ok para el dominio registrable dado. Nunca lanza
    excepciones: cualquier fallo se traduce en whois_ok=False y el resto
    de los campos en None.
    """
    if not registrable_domain:
        return dict(_EMPTY_RESULT)

    cached = _cache.get(registrable_domain)
    if cached is not None and (time.time() - cached[0]) < _CACHE_TTL_SECONDS:
        return dict(cached[1])

    try:
        result = _lookup_domain_info_uncached(registrable_domain)
    except Exception as e:
        # Defensa en profundidad: aunque cada paso interno ya atrapa sus
        # propios errores, esto garantiza que un fallo inesperado en esta
        # funcion jamas se propague hacia build_analysis_result().
        logger.warning(f"Fallo inesperado en lookup WHOIS de '{registrable_domain}': {str(e)}")
        result = dict(_EMPTY_RESULT)

    _cache[registrable_domain] = (time.time(), dict(result))
    return result


def _lookup_domain_info_uncached(domain):
    result = dict(_EMPTY_RESULT)

    parsed = _query_python_whois(domain)
    if parsed is not None:
        fecha = parsed.get("creation_date")
        if fecha:
            result["fecha_creacion_dominio"] = fecha
            result["dominio_registrado_en"] = parsed.get("registrar")
            result["pais"] = parsed.get("country")
            result["dnssec"] = parsed.get("dnssec")
            result["whois_ok"] = True
            return result

    # Fallback: consulta cruda al registro .co, para dominios de esa
    # familia cuando python-whois no devolvio fecha de creacion. Objetivo
    # no negociable del encargo: .co y .com.co deben devolver fecha.
    if _is_co_family(domain):
        raw_text = _raw_whois_query(_CO_REGISTRY_WHOIS_SERVER, domain)
        if raw_text:
            fallback_parsed = _parse_raw_whois(raw_text)
            fecha = fallback_parsed.get("creation_date")
            if fecha:
                result["fecha_creacion_dominio"] = fecha
                result["dominio_registrado_en"] = fallback_parsed.get("registrar")
                result["pais"] = fallback_parsed.get("country")
                result["dnssec"] = fallback_parsed.get("dnssec")
                result["whois_ok"] = True
                return result

    return result


def _is_co_family(domain):
    labels = domain.split(".")
    return bool(labels) and labels[-1] == "co"


def _query_python_whois(domain, timeout=WHOIS_TIMEOUT_SECONDS, attempts=_PYTHON_WHOIS_ATTEMPTS):
    """
    Consulta con python-whois (socket puro, sin binario del sistema).
    Reintenta hasta `attempts` veces ante fallos transitorios de
    conexion/resolucion (observados incluso contra TLDs comunes como
    .com). Devuelve un dict normalizado (creation_date ya formateada como
    'YYYY-MM-DD') o None si no se obtuvo fecha en ningun intento.
    """
    if _python_whois is None:
        logger.warning("python-whois no esta instalado; se omite la consulta WHOIS primaria")
        return None

    for attempt in range(1, attempts + 1):
        try:
            raw_result = _python_whois.whois(domain, timeout=timeout)
        except Exception as e:
            logger.debug(f"python-whois fallo para '{domain}' (intento {attempt}/{attempts}): {str(e)}")
            continue

        creation_date = getattr(raw_result, "creation_date", None) if raw_result else None
        fecha = _earliest_date(creation_date)
        if fecha:
            return {
                "creation_date": fecha,
                "registrar": _first_value(getattr(raw_result, "registrar", None)),
                "country": _first_value(getattr(raw_result, "country", None)),
                "dnssec": _first_value(getattr(raw_result, "dnssec", None)),
            }

    return None


def _raw_whois_query(server, domain, timeout=WHOIS_TIMEOUT_SECONDS, attempts=2):
    """
    Consulta WHOIS cruda por socket (puerto 43), sin depender del binario
    whois del sistema. Devuelve el texto crudo de la respuesta, o None si
    hubo cualquier error en todos los intentos.
    """
    for attempt in range(1, attempts + 1):
        try:
            with socket.create_connection((server, 43), timeout=timeout) as sock:
                sock.sendall((domain + "\r\n").encode("ascii", errors="ignore"))
                chunks = []
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug(
                f"Consulta WHOIS cruda a '{server}' para '{domain}' fallo (intento {attempt}/{attempts}): {str(e)}"
            )
            continue
    return None


def _parse_raw_whois(text):
    """
    Extrae fecha de creacion / registrador / pais / dnssec de una
    respuesta WHOIS cruda con parseo laxo basado en regex (formato
    "Campo: valor" por linea, comun a la mayoria de registros). La fecha
    ya se devuelve formateada como 'YYYY-MM-DD'.
    """
    result = {}
    for field, pattern in _RAW_FIELD_PATTERNS.items():
        match = pattern.search(text)
        result[field] = match.group(1).strip() if match else None

    result["creation_date"] = _earliest_date(result.get("creation_date"))
    return result


def _earliest_date(creation_date):
    """
    Normaliza creation_date (puede venir como datetime, string, o una
    lista/tupla de cualquiera de esos -segun la fuente-) a un string
    'YYYY-MM-DD' con la fecha MAS ANTIGUA encontrada, o None si no hay
    nada utilizable.
    """
    if creation_date is None:
        return None

    candidates = creation_date if isinstance(creation_date, (list, tuple)) else [creation_date]

    dates = []
    for candidate in candidates:
        if isinstance(candidate, datetime):
            dates.append(candidate.replace(tzinfo=None))
        elif isinstance(candidate, str):
            match = _DATE_IN_STRING_RE.search(candidate)
            if match:
                try:
                    dates.append(datetime.strptime(match.group(1), "%Y-%m-%d"))
                except ValueError:
                    continue

    if not dates:
        return None

    return min(dates).strftime("%Y-%m-%d")


def _first_value(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value
