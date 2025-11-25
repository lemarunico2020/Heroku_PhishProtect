from flask import Flask, request, Response
import tempfile
import os
import logging
import re
import hashlib
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from ioc_finder import find_iocs
import json
from logging.handlers import RotatingFileHandler
from functools import wraps
import extract_msg  # Importación para archivos MSG

app = Flask(__name__)

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
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

# Obtener la API Key de las variables de entorno
API_KEY = os.environ.get('PHISHPROTECT_API_KEY')

if not API_KEY:
    logger.warning("PHISHPROTECT_API_KEY no está configurada en las variables de entorno")

# Obtener límites de tamaño de las variables de entorno
MAX_FILE_SIZE_MB = int(os.environ.get('MAX_FILE_SIZE_MB', 18))
MAX_CONTENT_SIZE_MB = int(os.environ.get('MAX_CONTENT_SIZE_MB', 2))
MAX_ATTACHMENT_SIZE_MB = int(os.environ.get('MAX_ATTACHMENT_SIZE_MB', 10))

# Configuración de límites de tamaño (en bytes)
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_CONTENT_ANALYSIS_SIZE = MAX_CONTENT_SIZE_MB * 1024 * 1024
MAX_ATTACHMENT_SIZE = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024

logger.info(f"Límites configurados: Archivo máx: {MAX_FILE_SIZE_MB}MB, Contenido máx: {MAX_CONTENT_SIZE_MB}MB, Adjunto máx: {MAX_ATTACHMENT_SIZE_MB}MB")

# Decorador para verificar la API Key
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si la API Key está configurada
        if not API_KEY:
            logger.error("API Key no configurada en el servidor")
            return json_response(create_json_response(
                status="error",
                error="API Key not configured on server"
            )), 500
            
        # Verificar si la API Key se proporciona en la solicitud
        request_api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not request_api_key:
            logger.warning("Solicitud sin API Key")
            return json_response(create_json_response(
                status="error",
                error="API Key required"
            )), 401
            
        # Verificar si la API Key es válida
        if request_api_key != API_KEY:
            logger.warning("API Key inválida proporcionada")
            return json_response(create_json_response(
                status="error",
                error="Invalid API Key"
            )), 403
            
        return f(*args, **kwargs)
    return decorated_function

def check_file_size(file, max_size_bytes=MAX_FILE_SIZE):
    """
    Verifica si el tamaño del archivo excede el límite máximo
    """
    file.seek(0, os.SEEK_END)
    file_size = file.tell()  # Tamaño en bytes
    file.seek(0)  # Volver al inicio del archivo
    if file_size > max_size_bytes:
        logger.warning(f"Archivo rechazado: {file_size/1024/1024:.2f} MB (límite: {max_size_bytes/1024/1024:.1f} MB)")
        return False, file_size, f"El archivo excede el tamaño máximo permitido de {max_size_bytes/1024/1024:.1f} MB (tamaño actual: {file_size/1024/1024:.2f} MB). Contacte al administrador si necesita procesar archivos más grandes."
    
    return True, file_size, ""

def create_json_response(status="success", data=None, error=None):
    """
    Crea una respuesta JSON estandarizada
    """
    response = {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.1"
    }

    if data is not None:
        response["data"] = data
    if error is not None:
        response["error"] = error

    return response

def json_response(data, status_code=200):
    """
    Crea una respuesta HTTP con JSON formateado (indentado)
    """
    return Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        status=status_code,
        mimetype='application/json'
    )

def calculate_file_hashes(file_data):
    """
    Calcula diferentes hashes (MD5, SHA1, SHA256) para un archivo
    """
    try:
        # Calcular MD5
        md5_hash = hashlib.md5(file_data).hexdigest()
        
        # Calcular SHA1
        sha1_hash = hashlib.sha1(file_data).hexdigest()
        
        # Calcular SHA256
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        return {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash
        }
    except Exception as e:
        logger.error(f"Error al calcular hashes: {str(e)}", exc_info=True)
        return {}

def parse_authentication_results(msg):
    """
    Parsea la cabecera Authentication-Results y extrae los resultados de SPF, DKIM y DMARC
    """
    try:
        auth_results_header = msg.get('authentication-results', '')

        if not auth_results_header:
            logger.debug("No se encontró la cabecera Authentication-Results")
            return {
                "spf": "NOT_FOUND",
                "dkim": "NOT_FOUND",
                "dmarc": "NOT_FOUND"
            }

        logger.debug(f"Authentication-Results header: {auth_results_header}")

        # Convertir a minúsculas para facilitar la búsqueda
        auth_results_lower = auth_results_header.lower()

        # Extraer resultado SPF
        spf_result = "NOT_FOUND"
        spf_match = re.search(r'spf\s*=\s*(pass|fail|neutral|softfail|none|temperror|permerror)', auth_results_lower)
        if spf_match:
            spf_result = spf_match.group(1).upper()

        # Extraer resultado DKIM
        dkim_result = "NOT_FOUND"
        dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|policy|temperror|permerror)', auth_results_lower)
        if dkim_match:
            dkim_result = dkim_match.group(1).upper()

        # Extraer resultado DMARC
        dmarc_result = "NOT_FOUND"
        dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)', auth_results_lower)
        if dmarc_match:
            dmarc_result = dmarc_match.group(1).upper()

        logger.debug(f"Parsed authentication results - SPF: {spf_result}, DKIM: {dkim_result}, DMARC: {dmarc_result}")

        return {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result
        }

    except Exception as e:
        logger.error(f"Error parsing authentication results: {str(e)}", exc_info=True)
        return {
            "spf": "ERROR",
            "dkim": "ERROR",
            "dmarc": "ERROR"
        }

def extract_email_headers(msg):
    """
    Extrae cabeceras adicionales del correo electrónico
    """
    try:
        # Extraer Return-Path
        return_path = msg.get('return-path', None)

        # Extraer Reply-To
        reply_to = msg.get('reply-to', None)

        # Extraer X-Originating-IP
        x_originating_ip = msg.get('x-originating-ip', None)

        # Extraer X-Mailer
        x_mailer = msg.get('x-mailer', None)

        # Extraer Authentication-Results (cabecera completa)
        authentication_results = msg.get('authentication-results', None)

        # Extraer cadena de Received headers
        received_chain = []
        received_headers = msg.get_all('received')
        if received_headers:
            for received in received_headers:
                if received:
                    received_chain.append(str(received))

        logger.debug(f"Cabeceras extraídas - Return-Path: {return_path}, Reply-To: {reply_to}, X-Originating-IP: {x_originating_ip}")

        return {
            "return_path": return_path,
            "reply_to": reply_to,
            "x_originating_ip": x_originating_ip,
            "x_mailer": x_mailer,
            "received_chain": received_chain,
            "authentication_results": authentication_results
        }

    except Exception as e:
        logger.error(f"Error extracting email headers: {str(e)}", exc_info=True)
        return {
            "return_path": None,
            "reply_to": None,
            "x_originating_ip": None,
            "x_mailer": None,
            "received_chain": [],
            "authentication_results": None
        }

def extract_msg_headers(msg):
    """
    Extrae cabeceras adicionales de un archivo MSG
    """
    try:
        # Inicializar valores por defecto
        return_path = None
        reply_to = None
        x_originating_ip = None
        x_mailer = None
        authentication_results = None
        received_chain = []

        # Intentar extraer cabeceras del header del MSG si está disponible
        if hasattr(msg, 'header') and msg.header:
            header_text = str(msg.header)

            # Parsear Return-Path
            return_path_match = re.search(r'Return-Path:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)', header_text, re.IGNORECASE | re.MULTILINE)
            if return_path_match:
                return_path = return_path_match.group(1).strip()

            # Parsear Reply-To
            reply_to_match = re.search(r'Reply-To:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)', header_text, re.IGNORECASE | re.MULTILINE)
            if reply_to_match:
                reply_to = reply_to_match.group(1).strip()
                # Limpiar posibles residuos de otros headers
                # Si contiene ":" seguido de otro header name, es un error de parseo
                if re.search(r'[A-Z][\w-]*:', reply_to):
                    reply_to = None

            # Parsear X-Originating-IP
            x_originating_ip_match = re.search(r'X-Originating-IP:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)', header_text, re.IGNORECASE | re.MULTILINE)
            if x_originating_ip_match:
                x_originating_ip = x_originating_ip_match.group(1).strip()

            # Parsear X-Mailer
            x_mailer_match = re.search(r'X-Mailer:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)', header_text, re.IGNORECASE | re.MULTILINE)
            if x_mailer_match:
                x_mailer = x_mailer_match.group(1).strip()

            # Parsear Authentication-Results
            auth_results_match = re.search(r'Authentication-Results:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)', header_text, re.IGNORECASE | re.MULTILINE)
            if auth_results_match:
                authentication_results = auth_results_match.group(1).strip()

            # Parsear Received headers (puede haber múltiples)
            received_matches = re.findall(r'Received:\s*(.+?)(?=\r?\nReceived:|\r?\n[A-Z][\w-]*:|$)', header_text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if received_matches:
                received_chain = [r.strip() for r in received_matches]

        logger.debug(f"Cabeceras MSG extraídas - Return-Path: {return_path}, Reply-To: {reply_to}, X-Originating-IP: {x_originating_ip}")

        return {
            "return_path": return_path,
            "reply_to": reply_to,
            "x_originating_ip": x_originating_ip,
            "x_mailer": x_mailer,
            "received_chain": received_chain,
            "authentication_results": authentication_results
        }

    except Exception as e:
        logger.error(f"Error extracting MSG headers: {str(e)}", exc_info=True)
        return {
            "return_path": None,
            "reply_to": None,
            "x_originating_ip": None,
            "x_mailer": None,
            "received_chain": [],
            "authentication_results": None
        }

def parse_email_date(msg):
    """
    Función para parsear la fecha del correo electrónico de manera robusta
    """
    try:
        # Primero intentamos obtener la fecha del encabezado 'Date'
        date_str = msg.get('date')
        if date_str:
            try:
                # Usar parsedate_to_datetime que maneja formatos estándar de email
                return parsedate_to_datetime(date_str).isoformat()
            except Exception as e:
                logger.warning(f"Error parsing standard date format: {e}")

        # Si falla, buscamos en otros encabezados comunes de fecha
        date_headers = [
            'Delivery-Date',
            'Received',
            'X-Original-Date',
            'X-Mail-Creation-Date',
            'Creation-Date'
        ]

        for header in date_headers:
            date_str = msg.get(header)
            if date_str:
                try:
                    # Para el encabezado 'Received', extraemos la primera fecha que encontremos
                    if header == 'Received':
                        # Buscar una fecha en el formato típico de Received
                        date_match = re.search(r';(.*?)(?:\(|\r|\n|$)', date_str)
                        if date_match:
                            date_str = date_match.group(1).strip()

                    return parsedate_to_datetime(date_str).isoformat()
                except Exception as e:
                    logger.warning(f"Error parsing date from {header}: {e}")
                    continue

        # Si no se encuentra ninguna fecha válida, devolver la fecha actual
        logger.warning("No valid date found in email headers, using current timestamp")
        return datetime.now(timezone.utc).isoformat()

    except Exception as e:
        logger.error(f"Error in parse_email_date: {str(e)}", exc_info=True)
        return datetime.now(timezone.utc).isoformat()

def extract_body(msg):
    """
    Función mejorada para extraer el cuerpo del correo electrónico
    """
    body_content = []
    
    if msg.is_multipart():
        logger.debug("Procesando mensaje multipart")
        for part in msg.walk():
            # Ignorar los contenedores multipart
            if part.get_content_maintype() == 'multipart':
                continue
                
            # Obtener el tipo de contenido
            content_type = part.get_content_type()
            logger.debug(f"Procesando parte con tipo de contenido: {content_type}")
            
            # Procesar contenido de texto
            if content_type.startswith('text/'):
                try:
                    # Intentar obtener la codificación del contenido
                    charset = part.get_content_charset()
                    if charset is None:
                        charset = 'utf-8'  # Fallback a UTF-8
                    
                    content = part.get_payload(decode=True)
                    if content:
                        # Limitar tamaño para evitar problemas con contenido muy grande
                        if len(content) > MAX_CONTENT_ANALYSIS_SIZE:
                            logger.warning(f"Contenido de parte muy grande ({len(content)} bytes), limitando a {MAX_CONTENT_ANALYSIS_SIZE} bytes")
                            content = content[:MAX_CONTENT_ANALYSIS_SIZE]
                            
                        # Intentar múltiples codificaciones si la primera falla
                        encodings = [charset, 'utf-8', 'latin1', 'cp1252', 'ascii', 'iso-8859-1']
                        decoded = None
                        
                        for encoding in encodings:
                            try:
                                decoded = content.decode(encoding)
                                logger.debug(f"Contenido decodificado exitosamente con {encoding}")
                                break
                            except Exception as e:
                                logger.debug(f"Fallo al decodificar con {encoding}: {str(e)}")
                                continue
                        
                        if decoded:
                            body_content.append(decoded)
                        else:
                            logger.warning("No se pudo decodificar el contenido con ninguna codificación")
                            
                except Exception as e:
                    logger.error(f"Error al procesar parte del mensaje: {str(e)}", exc_info=True)
    else:
        logger.debug("Procesando mensaje simple (no multipart)")
        try:
            charset = msg.get_content_charset() or 'utf-8'
            content = msg.get_payload(decode=True)
            if content:
                # Limitar tamaño para evitar problemas con contenido muy grande
                if len(content) > MAX_CONTENT_ANALYSIS_SIZE:
                    logger.warning(f"Contenido de mensaje simple muy grande ({len(content)} bytes), limitando a {MAX_CONTENT_ANALYSIS_SIZE} bytes")
                    content = content[:MAX_CONTENT_ANALYSIS_SIZE]
                    
                try:
                    decoded = content.decode(charset)
                    body_content.append(decoded)
                except UnicodeDecodeError:
                    # Intentar con codificaciones alternativas
                    for encoding in ['utf-8', 'latin1', 'cp1252', 'ascii', 'iso-8859-1']:
                        try:
                            decoded = content.decode(encoding)
                            body_content.append(decoded)
                            logger.debug(f"Contenido decodificado con codificación alternativa: {encoding}")
                            break
                        except UnicodeDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Error al procesar mensaje simple: {str(e)}", exc_info=True)

    return "\n".join(body_content)

def extract_eml_attachments(msg):
    """
    Extrae archivos adjuntos de un mensaje EML y calcula sus hashes
    Con optimizaciones para manejar adjuntos grandes
    """
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
                
            # Verificar si es un adjunto
            filename = part.get_filename()
            if filename:
                try:
                    logger.debug(f"Procesando adjunto: {filename}")
                    content_type = part.get_content_type()
                    
                    # Obtener datos del adjunto
                    attachment_data = part.get_payload(decode=True)
                    if attachment_data:
                        # Calcular hashes solo para adjuntos pequeños
                        attachment_size = len(attachment_data)
                        attachment_info = {
                            "filename": filename,
                            "content_type": content_type,
                            "size": attachment_size
                        }
                        
                        if attachment_size <= MAX_ATTACHMENT_SIZE:
                            # Calcular hashes
                            hashes = calculate_file_hashes(attachment_data)
                            attachment_info["hashes"] = hashes
                        else:
                            logger.warning(f"Adjunto demasiado grande para calcular hashes: {filename}, tamaño: {attachment_size} bytes")
                            attachment_info["hashes"] = {
                                "info": "Adjunto demasiado grande para calcular hashes"
                            }
                        
                        attachments.append(attachment_info)
                        logger.debug(f"Adjunto procesado: {filename}, tamaño: {attachment_size} bytes")
                except Exception as e:
                    logger.error(f"Error al procesar adjunto {filename}: {str(e)}", exc_info=True)
    
    return attachments

def analyze_eml(eml_path):
    """
    Analiza un archivo EML y extrae IOCs
    Con optimizaciones para rendimiento mejorado
    """
    logger.info(f"Iniciando análisis del archivo EML: {eml_path}")
    try:
        # Verificar el tamaño del archivo
        file_size = os.path.getsize(eml_path)
        if file_size > MAX_FILE_SIZE:
            logger.warning(f"Archivo EML demasiado grande: {file_size} bytes")
            raise ValueError(f"El archivo excede el tamaño máximo permitido de {MAX_FILE_SIZE/1024/1024:.1f} MB")
        
        with open(eml_path, 'rb') as f:
            logger.debug("Leyendo el archivo EML...")
            msg = BytesParser(policy=policy.default).parse(f)
            logger.debug("Archivo EML parseado correctamente")
            
            # Logging de información básica del correo
            logger.info(f"Procesando correo con Subject: {msg.get('subject', 'No subject')}")
            logger.debug(f"Content-Type del mensaje: {msg.get_content_type()}")
            logger.debug(f"Charset del mensaje: {msg.get_content_charset()}")

        # Extraer direcciones y dominios del destinatario
        logger.debug("Extrayendo direcciones y dominios del destinatario")
        recipient_addresses = set()
        recipient_domains = set()
        
        for header in ['to', 'cc', 'bcc']:
            if msg[header]:
                addresses = str(msg[header]).split(',')
                for addr in addresses:
                    addr = addr.strip().lower()
                    recipient_addresses.add(addr)
                    if '@' in addr:
                        domain = addr.split('@')[1].strip('>')
                        recipient_domains.add(domain)
        
        logger.debug(f"Direcciones del destinatario: {recipient_addresses}")
        logger.debug(f"Dominios del destinatario: {recipient_domains}")

        # Extraer cabeceras para análisis
        logger.debug("Extrayendo cabeceras para análisis")
        header_content = []
        for header in ['from', 'subject', 'received', 'x-originating-ip', 'authentication-results']:
            if msg[header]:
                header_content.append(str(msg[header]))
        logger.debug(f"Contenido de cabeceras: {header_content}")

        # Extraer cuerpo del correo electrónico
        logger.debug("Extrayendo cuerpo del correo electrónico")
        email_body = extract_body(msg)
        
        if not email_body:
            logger.warning("No se pudo extraer el cuerpo del correo electrónico")
        else:
            logger.debug("Cuerpo del correo extraído exitosamente")

        # Obtener la fecha del correo usando la nueva función
        email_date = parse_email_date(msg)
        logger.debug(f"Fecha del correo extraída: {email_date}")

        # Parsear resultados de autenticación (SPF, DKIM, DMARC)
        logger.debug("Parseando resultados de autenticación")
        auth_results = parse_authentication_results(msg)
        logger.debug(f"Resultados de autenticación: {auth_results}")

        # Extraer cabeceras adicionales del email
        logger.debug("Extrayendo cabeceras adicionales del email")
        email_headers = extract_email_headers(msg)
        logger.debug(f"Cabeceras extraídas: {email_headers}")

        # Extraer adjuntos y calcular hashes
        logger.debug("Extrayendo archivos adjuntos")
        attachments = extract_eml_attachments(msg)
        logger.debug(f"Se encontraron {len(attachments)} adjuntos")

        # Preparar contenido adicional de cabeceras para análisis de IOCs
        additional_headers = []
        if email_headers.get('return_path'):
            additional_headers.append(f"Return-Path: {email_headers['return_path']}")
        if email_headers.get('reply_to'):
            additional_headers.append(f"Reply-To: {email_headers['reply_to']}")
        if email_headers.get('x_originating_ip'):
            additional_headers.append(f"X-Originating-IP: {email_headers['x_originating_ip']}")
        if email_headers.get('x_mailer'):
            additional_headers.append(f"X-Mailer: {email_headers['x_mailer']}")
        if email_headers.get('received_chain'):
            additional_headers.extend(email_headers['received_chain'])
        if email_headers.get('authentication_results'):
            additional_headers.append(f"Authentication-Results: {email_headers['authentication_results']}")

        # Combinar todo el contenido para análisis (incluye cabeceras adicionales)
        full_content = "\n".join(header_content + additional_headers + [email_body])
        logger.debug("Contenido completo preparado para análisis de IOCs")

        # Limitar el tamaño del contenido a analizar para evitar timeouts
        if len(full_content) > MAX_CONTENT_ANALYSIS_SIZE:
            logger.warning(f"Contenido para análisis demasiado grande ({len(full_content)} bytes), limitando a {MAX_CONTENT_ANALYSIS_SIZE} bytes")
            analyzed_content = full_content[:MAX_CONTENT_ANALYSIS_SIZE]
        else:
            analyzed_content = full_content

        # Encontrar IOCs con manejo de excepciones mejorado
        logger.debug("Buscando Indicadores de Compromiso (IOCs)")
        try:
            iocs = find_iocs(analyzed_content)
            logger.debug(f"IOCs encontrados: {iocs}")
        except Exception as e:
            logger.error(f"Error durante la búsqueda de IOCs: {str(e)}", exc_info=True)
            # Proporcionar un conjunto vacío de IOCs para continuar
            iocs = {
                'domains': set(),
                'email_addresses': set(),
                'ipv4s': set(),
                'ipv6s': set(),
                'urls': set(),
                'asns': set(),
                'cidr_ranges': set(),
                'md5s': set(),
                'sha1s': set(),
                'sha256s': set(),
                'sha512s': set(),
                'file_paths': set(),
                'registry_key_paths': set(),
                'mac_addresses': set(),
                'user_agents': set()
            }
            logger.warning("Usando conjunto vacío de IOCs debido a error en procesamiento")
        
        # Agregar hashes de los adjuntos a los IOCs encontrados
        attachment_md5s = set(iocs.get('md5s', set()))
        attachment_sha1s = set(iocs.get('sha1s', set()))
        attachment_sha256s = set(iocs.get('sha256s', set()))
        
        for attachment in attachments:
            if 'hashes' in attachment and isinstance(attachment['hashes'], dict) and 'info' not in attachment['hashes']:
                if 'md5' in attachment['hashes']:
                    attachment_md5s.add(attachment['hashes']['md5'])
                if 'sha1' in attachment['hashes']:
                    attachment_sha1s.add(attachment['hashes']['sha1'])
                if 'sha256' in attachment['hashes']:
                    attachment_sha256s.add(attachment['hashes']['sha256'])
                    
        # Actualizar IOCs con los hashes de los adjuntos
        iocs['md5s'] = attachment_md5s
        iocs['sha1s'] = attachment_sha1s
        iocs['sha256s'] = attachment_sha256s

        # Filtrar direcciones y dominios del destinatario
        logger.debug("Filtrando direcciones y dominios del destinatario")
        filtered_emails = set(addr for addr in iocs.get('email_addresses', set()) 
                            if addr.lower() not in recipient_addresses)
        filtered_domains = set(domain for domain in iocs.get('domains', set()) 
                             if domain.lower() not in recipient_domains)

        structured_iocs = {
            "network_indicators": {
                "domains": list(filtered_domains),
                "ipv4": list(iocs.get('ipv4s', set())),
                "ipv6": list(iocs.get('ipv6s', set())),
                "urls": list(iocs.get('urls', set())),
                "email_addresses": list(filtered_emails),
                "asns": list(iocs.get('asns', set())),
                "cidr_ranges": list(iocs.get('cidr_ranges', set()))
            },
            "file_indicators": {
                "md5_hashes": list(iocs.get('md5s', set())),
                "sha1_hashes": list(iocs.get('sha1s', set())),
                "sha256_hashes": list(iocs.get('sha256s', set())),
                "sha512_hashes": list(iocs.get('sha512s', set())),
                "file_paths": list(iocs.get('file_paths', set()))
            },
            "system_indicators": {
                "registry_keys": list(iocs.get('registry_key_paths', set())),
                "mac_addresses": list(iocs.get('mac_addresses', set())),
                "user_agents": list(iocs.get('user_agents', set()))
            }
        }
        
        # Generar ID único para el análisis
        dt = datetime.now(timezone.utc)
        millis = dt.microsecond // 1000
        analysis_id = f"IOC-{dt.strftime('%Y%m%d-%H%M%S')}-{millis:03d}"
        
        analysis_result = {
            "analysis_metadata": {
                "analysis_id": analysis_id,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "file_analyzed": eml_path,
                "file_type": "eml"
            },
            "email_metadata": {
                "from": str(msg.get("from", "")),
                "to": str(msg.get("to", "")),
                "subject": str(msg.get("subject", "")),
                "date": email_date,
                "body_extracted": bool(email_body),
                "body": email_body,
                "attachments": attachments,
                "authentication": {
                    "spf": auth_results["spf"],
                    "dkim": auth_results["dkim"],
                    "dmarc": auth_results["dmarc"]
                }
            },
            "cabeceras_email": {
                "return_path": email_headers["return_path"],
                "reply_to": email_headers["reply_to"],
                "x_originating_ip": email_headers["x_originating_ip"],
                "x_mailer": email_headers["x_mailer"],
                "received_chain": email_headers["received_chain"],
                "authentication_results": email_headers["authentication_results"]
            },
            "findings": structured_iocs
        }
        
        logger.info("Análisis completado con éxito")
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error al analizar el archivo EML: {str(e)}", exc_info=True)
        raise

def analyze_msg(msg_path):
    """
    Analiza un archivo MSG (Outlook) y extrae IOCs
    Con optimizaciones para rendimiento mejorado
    """
    logger.info(f"Iniciando análisis del archivo MSG: {msg_path}")
    msg = None
    try:
        # Verificar el tamaño del archivo
        file_size = os.path.getsize(msg_path)
        if file_size > MAX_FILE_SIZE:
            logger.warning(f"Archivo MSG demasiado grande: {file_size} bytes")
            raise ValueError(f"El archivo excede el tamaño máximo permitido de {MAX_FILE_SIZE/1024/1024:.1f} MB")

        # Usar extract_msg para abrir el archivo MSG
        logger.debug("Leyendo el archivo MSG...")
        msg = extract_msg.openMsg(msg_path)
        logger.debug("Archivo MSG abierto correctamente")
        
        # Logging de información básica del correo
        logger.info(f"Procesando correo con Subject: {msg.subject}")
        
        # Extraer direcciones y dominios del destinatario
        logger.debug("Extrayendo direcciones y dominios del destinatario")
        recipient_addresses = set()
        recipient_domains = set()
        
        # Procesar destinatarios (to, cc y bcc)
        for recipient in msg.recipients:
            if hasattr(recipient, 'email') and recipient.email:
                addr = recipient.email.lower()
                recipient_addresses.add(addr)
                if '@' in addr:
                    domain = addr.split('@')[1]
                    recipient_domains.add(domain)
        
        logger.debug(f"Direcciones del destinatario: {recipient_addresses}")
        logger.debug(f"Dominios del destinatario: {recipient_domains}")
        
        # Extraer cabeceras para análisis
        logger.debug("Extrayendo datos de cabecera para análisis")
        header_content = []
        
        # Añadir información del remitente
        if msg.sender:
            header_content.append(f"From: {msg.sender}")
        
        # Añadir asunto
        if msg.subject:
            header_content.append(f"Subject: {msg.subject}")
        
        # Extraer cuerpo del correo electrónico
        logger.debug("Extrayendo cuerpo del correo electrónico")
        email_body = msg.body
        
        # Limitar tamaño del cuerpo para evitar problemas de rendimiento
        if email_body and len(email_body) > MAX_CONTENT_ANALYSIS_SIZE:
            logger.warning(f"Cuerpo del correo MSG demasiado grande ({len(email_body)} bytes), limitando a {MAX_CONTENT_ANALYSIS_SIZE} bytes")
            email_body = email_body[:MAX_CONTENT_ANALYSIS_SIZE]
        
        if not email_body:
            logger.warning("No se pudo extraer el cuerpo del correo electrónico")
        else:
            logger.debug("Cuerpo del correo extraído exitosamente")
        
        # Obtener la fecha del correo
        if msg.date:
            # Verificar si msg.date ya es un string o un objeto datetime
            if isinstance(msg.date, str):
                email_date = msg.date
            else:
                try:
                    email_date = msg.date.isoformat()
                except AttributeError:
                    # Si no tiene isoformat, intentar convertir a string
                    email_date = str(msg.date)
        else:
            email_date = datetime.now(timezone.utc).isoformat()
        logger.debug(f"Fecha del correo extraída: {email_date}")

        # Extraer cabeceras adicionales del MSG
        logger.debug("Extrayendo cabeceras adicionales del MSG")
        msg_headers = extract_msg_headers(msg)
        logger.debug(f"Cabeceras MSG extraídas: {msg_headers}")

        # Parsear resultados de autenticación (SPF, DKIM, DMARC) desde las cabeceras del MSG
        logger.debug("Parseando resultados de autenticación para MSG")
        auth_results = {"spf": "NOT_FOUND", "dkim": "NOT_FOUND", "dmarc": "NOT_FOUND"}
        try:
            # Intentar obtener las cabeceras de transporte si están disponibles
            if hasattr(msg, 'header') and msg.header:
                # Buscar en las cabeceras del mensaje
                header_text = str(msg.header)
                auth_results_lower = header_text.lower()

                # Extraer resultado SPF
                spf_match = re.search(r'spf\s*=\s*(pass|fail|neutral|softfail|none|temperror|permerror)', auth_results_lower)
                if spf_match:
                    auth_results["spf"] = spf_match.group(1).upper()

                # Extraer resultado DKIM
                dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|policy|temperror|permerror)', auth_results_lower)
                if dkim_match:
                    auth_results["dkim"] = dkim_match.group(1).upper()

                # Extraer resultado DMARC
                dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)', auth_results_lower)
                if dmarc_match:
                    auth_results["dmarc"] = dmarc_match.group(1).upper()

                logger.debug(f"Resultados de autenticación MSG: {auth_results}")
        except Exception as e:
            logger.warning(f"No se pudieron parsear los resultados de autenticación del MSG: {str(e)}")

        # Procesar adjuntos y calcular hashes
        logger.debug("Procesando adjuntos del correo MSG")
        attachments_info = []
        
        for attachment in msg.attachments:
            try:
                if hasattr(attachment, 'longFilename') and attachment.longFilename:
                    attachment_data = attachment.data if hasattr(attachment, 'data') else None
                    
                    if attachment_data:
                        attachment_size = len(attachment_data)
                        
                        attachment_info = {
                            "filename": attachment.longFilename,
                            "size": attachment_size
                        }
                        
                        # Solo calcular hashes para adjuntos pequeños
                        if attachment_size <= MAX_ATTACHMENT_SIZE:
                            hashes = calculate_file_hashes(attachment_data)
                            attachment_info["hashes"] = hashes
                        else:
                            logger.warning(f"Adjunto demasiado grande para calcular hashes: {attachment.longFilename}, tamaño: {attachment_size} bytes")
                            attachment_info["hashes"] = {
                                "info": "Adjunto demasiado grande para calcular hashes"
                            }
                        
                        attachments_info.append(attachment_info)
                        logger.debug(f"Adjunto procesado: {attachment.longFilename}, tamaño: {attachment_size} bytes")
            except Exception as e:
                logger.error(f"Error al procesar adjunto {getattr(attachment, 'longFilename', 'desconocido')}: {str(e)}", exc_info=True)

        # Preparar contenido adicional de cabeceras para análisis de IOCs
        additional_headers = []
        if msg_headers.get('return_path'):
            additional_headers.append(f"Return-Path: {msg_headers['return_path']}")
        if msg_headers.get('reply_to'):
            additional_headers.append(f"Reply-To: {msg_headers['reply_to']}")
        if msg_headers.get('x_originating_ip'):
            additional_headers.append(f"X-Originating-IP: {msg_headers['x_originating_ip']}")
        if msg_headers.get('x_mailer'):
            additional_headers.append(f"X-Mailer: {msg_headers['x_mailer']}")
        if msg_headers.get('received_chain'):
            additional_headers.extend(msg_headers['received_chain'])
        if msg_headers.get('authentication_results'):
            additional_headers.append(f"Authentication-Results: {msg_headers['authentication_results']}")

        # Combinar todo el contenido para análisis (incluye cabeceras adicionales)
        full_content = "\n".join(header_content + additional_headers + [email_body]) if email_body else "\n".join(header_content + additional_headers)
        logger.debug("Contenido completo preparado para análisis de IOCs")
        
        # Limitar el tamaño del contenido a analizar para evitar timeouts
        if len(full_content) > MAX_CONTENT_ANALYSIS_SIZE:
            logger.warning(f"Contenido para análisis demasiado grande ({len(full_content)} bytes), limitando a {MAX_CONTENT_ANALYSIS_SIZE} bytes")
            analyzed_content = full_content[:MAX_CONTENT_ANALYSIS_SIZE]
        else:
            analyzed_content = full_content
        
        # Encontrar IOCs con manejo de excepciones mejorado
        logger.debug("Buscando Indicadores de Compromiso (IOCs)")
        try:
            iocs = find_iocs(analyzed_content)
            logger.debug(f"IOCs encontrados: {iocs}")
        except Exception as e:
            logger.error(f"Error durante la búsqueda de IOCs: {str(e)}", exc_info=True)
            # Proporcionar un conjunto vacío de IOCs para continuar
            iocs = {
                'domains': set(),
                'email_addresses': set(),
                'ipv4s': set(),
                'ipv6s': set(),
                'urls': set(),
                'asns': set(),
                'cidr_ranges': set(),
                'md5s': set(),
                'sha1s': set(),
                'sha256s': set(),
                'sha512s': set(),
                'file_paths': set(),
                'registry_key_paths': set(),
                'mac_addresses': set(),
                'user_agents': set()
            }
            logger.warning("Usando conjunto vacío de IOCs debido a error en procesamiento")
        
        # Agregar hashes de los adjuntos a los IOCs encontrados
        attachment_md5s = set(iocs.get('md5s', set()))
        attachment_sha1s = set(iocs.get('sha1s', set()))
        attachment_sha256s = set(iocs.get('sha256s', set()))
        
        for attachment in attachments_info:
            if 'hashes' in attachment and isinstance(attachment['hashes'], dict) and 'info' not in attachment['hashes']:
                if 'md5' in attachment['hashes']:
                    attachment_md5s.add(attachment['hashes']['md5'])
                if 'sha1' in attachment['hashes']:
                    attachment_sha1s.add(attachment['hashes']['sha1'])
                if 'sha256' in attachment['hashes']:
                    attachment_sha256s.add(attachment['hashes']['sha256'])
                    
        # Actualizar IOCs con los hashes de los adjuntos
        iocs['md5s'] = attachment_md5s
        iocs['sha1s'] = attachment_sha1s
        iocs['sha256s'] = attachment_sha256s
        
        # Filtrar direcciones y dominios del destinatario
        logger.debug("Filtrando direcciones y dominios del destinatario")
        filtered_emails = set(addr for addr in iocs.get('email_addresses', set()) 
                            if addr.lower() not in recipient_addresses)
        filtered_domains = set(domain for domain in iocs.get('domains', set()) 
                             if domain.lower() not in recipient_domains)
        
        structured_iocs = {
            "network_indicators": {
                "domains": list(filtered_domains),
                "ipv4": list(iocs.get('ipv4s', set())),
                "ipv6": list(iocs.get('ipv6s', set())),
                "urls": list(iocs.get('urls', set())),
                "email_addresses": list(filtered_emails),
                "asns": list(iocs.get('asns', set())),
                "cidr_ranges": list(iocs.get('cidr_ranges', set()))
            },
            "file_indicators": {
                "md5_hashes": list(iocs.get('md5s', set())),
                "sha1_hashes": list(iocs.get('sha1s', set())),
                "sha256_hashes": list(iocs.get('sha256s', set())),
                "sha512_hashes": list(iocs.get('sha512s', set())),
                "file_paths": list(iocs.get('file_paths', set()))
            },
            "system_indicators": {
                "registry_keys": list(iocs.get('registry_key_paths', set())),
                "mac_addresses": list(iocs.get('mac_addresses', set())),
                "user_agents": list(iocs.get('user_agents', set()))
            }
        }
        
        # Generar ID único para el análisis
        dt = datetime.now(timezone.utc)
        millis = dt.microsecond // 1000
        analysis_id = f"IOC-{dt.strftime('%Y%m%d-%H%M%S')}-{millis:03d}"
        
        analysis_result = {
            "analysis_metadata": {
                "analysis_id": analysis_id,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "file_analyzed": msg_path,
                "file_type": "msg"
            },
            "email_metadata": {
                "from": msg.sender if msg.sender else "",
                "to": "; ".join([r.email for r in msg.recipients if hasattr(r, 'email') and r.email]),
                "subject": msg.subject if msg.subject else "",
                "date": email_date,
                "body_extracted": bool(email_body),
                "body": email_body,
                "attachments": attachments_info,
                "authentication": {
                    "spf": auth_results["spf"],
                    "dkim": auth_results["dkim"],
                    "dmarc": auth_results["dmarc"]
                }
            },
            "cabeceras_email": {
                "return_path": msg_headers["return_path"],
                "reply_to": msg_headers["reply_to"],
                "x_originating_ip": msg_headers["x_originating_ip"],
                "x_mailer": msg_headers["x_mailer"],
                "received_chain": msg_headers["received_chain"],
                "authentication_results": msg_headers["authentication_results"]
            },
            "findings": structured_iocs
        }

        logger.info("Análisis completado con éxito")
        return analysis_result

    except Exception as e:
        logger.error(f"Error al analizar el archivo MSG: {str(e)}", exc_info=True)
        raise
    finally:
        # Cerrar el objeto MSG para liberar el archivo
        if msg is not None:
            try:
                msg.close()
                logger.debug("Objeto MSG cerrado correctamente")
            except Exception as e:
                logger.warning(f"Error al cerrar el objeto MSG: {str(e)}")

@app.route('/api/v1/analyze_email', methods=['POST'])
@require_api_key
def analyze_email_file():
    """
    Endpoint unificado para analizar archivos de correo electrónico (EML y MSG)
    Versión mejorada con mayor flexibilidad y optimizaciones
    """
    logger.info("Recibida solicitud de análisis de correo electrónico")
    try:
        # Buscar el archivo en cualquiera de los posibles campos del formulario
        file = None
        file_field_name = None
        
        # Posibles nombres de campo para archivos
        field_names = ['email_file', 'eml_file', 'msg_file', 'file']
        
        for field in field_names:
            if field in request.files and request.files[field].filename != '':
                file = request.files[field]
                file_field_name = field
                break
        
        # Si no se encuentra ningún archivo
        if not file:
            # Verificar si hay algún archivo, aunque esté en otro campo
            all_files = list(request.files.values())
            if all_files and len(all_files) > 0 and all_files[0].filename != '':
                file = all_files[0]
                file_field_name = list(request.files.keys())[0]
                logger.debug(f"Encontrado archivo en campo alternativo: {file_field_name}")
            else:
                logger.warning("No se ha subido ningún archivo")
                return json_response(create_json_response(
                    status="error",
                    error="No file uploaded"
                )), 400
            
        logger.debug(f"Nombre del archivo recibido: {file.filename} en campo: {file_field_name}")
        
        if file.filename == '':
            logger.warning("No se ha seleccionado ningún archivo")
            return json_response(create_json_response(
                status="error",
                error="No file selected"
            )), 400
        
        # Verificar el tamaño del archivo
        size_ok, file_size, error_message = check_file_size(file, MAX_FILE_SIZE)
        if not size_ok:
            logger.warning(f"El archivo excede el tamaño máximo: {file_size} bytes")
            return json_response(create_json_response(
                status="error",
                error=error_message
            )), 413
            
        # Determinar el tipo de archivo basado en la extensión y contenido
        file_extension = file.filename.lower().split('.')[-1] if '.' in file.filename else ''
        
        # Guardar el archivo temporalmente para poder analizarlo
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as temp_file:
            logger.debug(f"Guardando archivo temporal en: {temp_file.name}")
            
            # Guardamos el archivo para poder examinarlo
            file.save(temp_file.name)
            
            temp_filename = temp_file.name
            
            # Intentamos determinar el tipo de archivo
            file_type_detected = None
            
            # Si la extensión es clara, la usamos
            if file_extension in ['eml', 'msg']:
                file_type_detected = file_extension
                logger.debug(f"Tipo de archivo determinado por extensión: {file_type_detected}")
                
            # Si no, intentamos determinar por el nombre del campo
            elif 'eml' in file_field_name.lower():
                file_type_detected = 'eml'
                logger.debug(f"Tipo de archivo determinado por nombre de campo: {file_type_detected}")
                
            elif 'msg' in file_field_name.lower():
                file_type_detected = 'msg'
                logger.debug(f"Tipo de archivo determinado por nombre de campo: {file_type_detected}")
                
            # Si aún no podemos determinar, intentamos examinar el contenido del archivo
            else:
                try:
                    # Intentar abrir como EML
                    with open(temp_filename, 'rb') as f:
                        try:
                            BytesParser(policy=policy.default).parse(f)
                            file_type_detected = 'eml'
                            logger.debug("Archivo detectado como EML por su contenido")
                            
                        except Exception as e:
                            logger.debug(f"No es un archivo EML válido: {str(e)}")
                            
                            # Intentar abrir como MSG
                            try:
                                test_msg = extract_msg.openMsg(temp_filename)
                                test_msg.close()  # Cerrar inmediatamente después de verificar
                                file_type_detected = 'msg'
                                logger.debug("Archivo detectado como MSG por su contenido")

                            except Exception as e:
                                logger.debug(f"No es un archivo MSG válido: {str(e)}")
                                
                except Exception as e:
                    logger.error(f"Error al intentar determinar el tipo de archivo: {str(e)}")
                    
            
            # Si no pudimos determinar el tipo, devolver error
            if not file_type_detected:
                # Eliminar el archivo temporal
                if os.path.exists(temp_filename):
                    os.remove(temp_filename)
                    
                logger.warning("No se pudo determinar el tipo de archivo")
                
                return json_response(create_json_response(
                    status="error",
                    error="File must be an EML or MSG file. Could not determine file type."
                
                )), 400
                
            
            # Asignar el tipo detectado
            file_extension = file_type_detected
            
        # El archivo ya fue guardado anteriormente para la detección del tipo
        logger.debug(f"Usando archivo temporal ya guardado: {temp_filename}")
            
        try:
            logger.debug(f"Iniciando análisis del archivo temporal: {temp_filename} como {file_extension}")
            
            # Analizar según el tipo de archivo
            if file_extension == 'eml':
                results = analyze_eml(temp_filename)
            else:  # msg
                results = analyze_msg(temp_filename)
                
            logger.info("Análisis exitoso, preparando respuesta")
            response = create_json_response(
                status="success",
                data=results
            )
            return json_response(response, 200)
            
        except ValueError as ve:
            # Manejar específicamente errores de valor (como tamaño excesivo)
            logger.warning(f"Error de validación: {str(ve)}")
            return json_response(create_json_response(
                status="error",
                error=str(ve)
            )), 413
            
        except Exception as e:
            logger.error(f"Error al analizar el archivo: {str(e)}", exc_info=True)
            return json_response(create_json_response(
                status="error",
                error=str(e)
            )), 500
            
        finally:
            if os.path.exists(temp_filename):
                logger.debug(f"Eliminando archivo temporal: {temp_filename}")
                os.remove(temp_filename)
                
    except Exception as e:
        logger.error(f"Error al procesar el archivo: {str(e)}", exc_info=True)
        return json_response(create_json_response(
            status="error",
            error=str(e)
        )), 500

# Mantener los endpoints originales por compatibilidad
@app.route('/api/v1/analyze_eml', methods=['POST'])
@require_api_key
def analyze_eml_file():
    """
    Endpoint para analizar archivos EML
    """
    logger.info("Recibida solicitud de análisis de EML")
    try:
        if 'eml_file' not in request.files:
            # Intentar buscar el archivo en otros campos comunes
            file = None
            for field in request.files:
                if request.files[field].filename.lower().endswith('.eml'):
                    file = request.files[field]
                    logger.debug(f"Archivo EML encontrado en campo alternativo: {field}")
                    break
            
            if not file:
                logger.warning("No se ha subido ningún archivo EML")
                return json_response(create_json_response(
                    status="error",
                    error="No EML file uploaded"
                )), 400
        else:
            file = request.files['eml_file']
            
        logger.debug(f"Nombre del archivo recibido: {file.filename}")
        
        if file.filename == '':
            logger.warning("No se ha seleccionado ningún archivo")
            return json_response(create_json_response(
                status="error",
                error="No file selected"
            )), 400
        
        # Verificar el tamaño del archivo
        size_ok, file_size = check_file_size(file, MAX_FILE_SIZE)
        if not size_ok:
            logger.warning(f"El archivo excede el tamaño máximo: {file_size} bytes")
            return json_response(create_json_response(
                status="error",
                error=f"El archivo excede el tamaño máximo permitido de {MAX_FILE_SIZE/1024/1024:.1f} MB (tamaño actual: {file_size/1024/1024:.2f} MB)"
            )), 413
            
        # Verificar si el archivo tiene extensión EML o si podemos detectar que es un EML
        if not file.filename.lower().endswith('.eml'):
            # Intentar determinar si es un archivo EML por su contenido
            with tempfile.NamedTemporaryFile(delete=False) as temp_check:
                file.save(temp_check.name)
                temp_check_filename = temp_check.name
                
            try:
                with open(temp_check_filename, 'rb') as f:
                    try:
                        BytesParser(policy=policy.default).parse(f)
                        logger.debug("Archivo detectado como EML por su contenido a pesar de no tener extensión .eml")
                        
                    except Exception as e:
                        logger.warning("El archivo no es un archivo EML válido")
                        
                        # Eliminar archivo temporal de verificación
                        if os.path.exists(temp_check_filename):
                            os.remove(temp_check_filename)
                            
                        return json_response(create_json_response(
                            status="error",
                            error="File must be an EML file"
                        
                        )), 400
                        
            except Exception as e:
                logger.warning(f"Error al verificar el contenido del archivo: {str(e)}")
                
                # Eliminar archivo temporal de verificación
                if os.path.exists(temp_check_filename):
                    os.remove(temp_check_filename)
                    
                return json_response(create_json_response(
                    status="error",
                    error="File must be an EML file"
                
                )), 400
                
            # Eliminar archivo temporal de verificación
            if os.path.exists(temp_check_filename):
                os.remove(temp_check_filename)
                
            # Volver a mover el puntero al inicio del archivo para poder guardarlo de nuevo
            file.seek(0)
            
        with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as temp_file:
            logger.debug(f"Guardando archivo temporal en: {temp_file.name}")
            file.save(temp_file.name)
            temp_filename = temp_file.name
            
        try:
            logger.debug(f"Iniciando análisis del archivo temporal: {temp_filename}")
            results = analyze_eml(temp_filename)
            logger.info("Análisis exitoso, preparando respuesta")
            response = create_json_response(
                status="success",
                data=results
            )
            return json_response(response, 200)
            
        except ValueError as ve:
            # Manejar específicamente errores de valor (como tamaño excesivo)
            logger.warning(f"Error de validación: {str(ve)}")
            return json_response(create_json_response(
                status="error",
                error=str(ve)
            )), 413
            
        except Exception as e:
            logger.error(f"Error al analizar el archivo EML: {str(e)}", exc_info=True)
            return json_response(create_json_response(
                status="error",
                error=str(e)
            )), 500
            
        finally:
            if os.path.exists(temp_filename):
                logger.debug(f"Eliminando archivo temporal: {temp_filename}")
                os.remove(temp_filename)
                
    except Exception as e:
        logger.error(f"Error al procesar el archivo EML: {str(e)}", exc_info=True)
        return json_response(create_json_response(
            status="error",
            error=str(e)
        )), 500

@app.route('/api/v1/analyze_msg', methods=['POST'])
@require_api_key
def analyze_msg_file():
    """
    Endpoint para analizar archivos MSG
    """
    logger.info("Recibida solicitud de análisis de MSG")
    try:
        if 'msg_file' not in request.files:
            # Intentar buscar el archivo en otros campos comunes
            file = None
            for field in request.files:
                if request.files[field].filename.lower().endswith('.msg'):
                    file = request.files[field]
                    logger.debug(f"Archivo MSG encontrado en campo alternativo: {field}")
                    break
            
            if not file:
                logger.warning("No se ha subido ningún archivo MSG")
                return json_response(create_json_response(
                    status="error",
                    error="No MSG file uploaded"
                )), 400
        else:
            file = request.files['msg_file']
            
        logger.debug(f"Nombre del archivo recibido: {file.filename}")
        
        if file.filename == '':
            logger.warning("No se ha seleccionado ningún archivo")
            return json_response(create_json_response(
                status="error",
                error="No file selected"
            )), 400
        
        # Verificar el tamaño del archivo
        size_ok, file_size = check_file_size(file, MAX_FILE_SIZE)
        if not size_ok:
            logger.warning(f"El archivo excede el tamaño máximo: {file_size} bytes")
            return json_response(create_json_response(
                status="error",
                error=f"El archivo excede el tamaño máximo permitido de {MAX_FILE_SIZE/1024/1024:.1f} MB (tamaño actual: {file_size/1024/1024:.2f} MB)"
            )), 413
            
        # Verificar si el archivo tiene extensión MSG o si podemos detectar que es un MSG
        if not file.filename.lower().endswith('.msg'):
            # Intentar determinar si es un archivo MSG por su contenido
            with tempfile.NamedTemporaryFile(delete=False) as temp_check:
                file.save(temp_check.name)
                temp_check_filename = temp_check.name
                
            try:
                try:
                    test_msg = extract_msg.openMsg(temp_check_filename)
                    test_msg.close()  # Cerrar inmediatamente después de verificar
                    logger.debug("Archivo detectado como MSG por su contenido a pesar de no tener extensión .msg")

                except Exception as e:
                    logger.warning("El archivo no es un archivo MSG válido")
                    
                    # Eliminar archivo temporal de verificación
                    if os.path.exists(temp_check_filename):
                        os.remove(temp_check_filename)
                        
                    return json_response(create_json_response(
                        status="error",
                        error="File must be an MSG file"
                    
                    )), 400
                    
            except Exception as e:
                logger.warning(f"Error al verificar el contenido del archivo: {str(e)}")
                
                # Eliminar archivo temporal de verificación
                if os.path.exists(temp_check_filename):
                    os.remove(temp_check_filename)
                    
                return json_response(create_json_response(
                    status="error",
                    error="File must be an MSG file"
                
                )), 400
                
            # Eliminar archivo temporal de verificación
            if os.path.exists(temp_check_filename):
                os.remove(temp_check_filename)
                
            # Volver a mover el puntero al inicio del archivo para poder guardarlo de nuevo
            file.seek(0)
            
        with tempfile.NamedTemporaryFile(delete=False, suffix='.msg') as temp_file:
            logger.debug(f"Guardando archivo temporal en: {temp_file.name}")
            file.save(temp_file.name)
            temp_filename = temp_file.name
            
        try:
            logger.debug(f"Iniciando análisis del archivo temporal: {temp_filename}")
            results = analyze_msg(temp_filename)
            logger.info("Análisis exitoso, preparando respuesta")
            response = create_json_response(
                status="success",
                data=results
            )
            return json_response(response, 200)
            
        except ValueError as ve:
            # Manejar específicamente errores de valor (como tamaño excesivo)
            logger.warning(f"Error de validación: {str(ve)}")
            return json_response(create_json_response(
                status="error",
                error=str(ve)
            )), 413
            
        except Exception as e:
            logger.error(f"Error al analizar el archivo MSG: {str(e)}", exc_info=True)
            return json_response(create_json_response(
                status="error",
                error=str(e)
            )), 500
            
        finally:
            if os.path.exists(temp_filename):
                logger.debug(f"Eliminando archivo temporal: {temp_filename}")
                os.remove(temp_filename)
                
    except Exception as e:
        logger.error(f"Error al procesar el archivo MSG: {str(e)}", exc_info=True)
        return json_response(create_json_response(
            status="error",
            error=str(e)
        )), 500

# Ruta para la página principal
@app.route('/', methods=['GET'])
def home():
    """
    Página principal que muestra información sobre la API
    """
    return """
    <html>
    <head>
        <title>PhishProtect API</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            h1 { color: #2c3e50; }
            .container { max-width: 800px; margin: 0 auto; }
            .endpoint { background-color: #f8f9fa; border-left: 4px solid #4CAF50; padding: 10px; margin-bottom: 20px; }
            code { background-color: #f1f1f1; padding: 2px 5px; border-radius: 3px; }
            .note { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PhishProtect API</h1>
            <p>Esta es la API de análisis de correos electrónicos PhishProtect. Para utilizar esta API, necesitas una API Key válida.</p>
            
            <div class="note">
                <strong>Nota:</strong> El tamaño máximo de archivo permitido es de 15MB. Los archivos más grandes serán rechazados.
            </div>
            
            <h2>Endpoints disponibles:</h2>
            
            <div class="endpoint">
                <h3>Analizar archivo de correo (Unificado)</h3>
                <p><code>POST /api/v1/analyze_email</code></p>
                <p>Este endpoint permite analizar archivos EML o MSG para extraer Indicadores de Compromiso (IOCs) y resultados de autenticación (SPF, DKIM, DMARC).</p>
                <p>Requiere autenticación mediante API Key.</p>
            </div>

            <div class="endpoint">
                <h3>Analizar archivo EML</h3>
                <p><code>POST /api/v1/analyze_eml</code></p>
                <p>Este endpoint permite analizar un archivo EML para extraer Indicadores de Compromiso (IOCs) y resultados de autenticación (SPF, DKIM, DMARC).</p>
                <p>Requiere autenticación mediante API Key.</p>
            </div>

            <div class="endpoint">
                <h3>Analizar archivo MSG</h3>
                <p><code>POST /api/v1/analyze_msg</code></p>
                <p>Este endpoint permite analizar un archivo MSG para extraer Indicadores de Compromiso (IOCs) y resultados de autenticación (SPF, DKIM, DMARC).</p>
                <p>Requiere autenticación mediante API Key.</p>
            </div>
            
            <div class="endpoint">
                <h3>Verificar autenticación</h3>
                <p><code>GET /api/v1/check_auth</code></p>
                <p>Este endpoint permite verificar si tu API Key es válida.</p>
            </div>
            
            <h2>Autenticación</h2>
            <p>Todas las solicitudes deben incluir una API Key válida de alguna de estas formas:</p>
            <ul>
                <li>Como encabezado HTTP: <code>X-API-Key: tu-api-key</code></li>
                <li>Como parámetro de URL: <code>?api_key=tu-api-key</code></li>
            </ul>
            
            <h2>Formatos soportados</h2>
            <p>La API soporta los siguientes formatos de correo electrónico:</p>
            <ul>
                <li><strong>EML</strong>: Formato estándar de correo electrónico</li>
                <li><strong>MSG</strong>: Formato de Microsoft Outlook</li>
            </ul>
            
            <h2>Límites y recomendaciones</h2>
            <ul>
                <li>Tamaño máximo de archivo: 15MB</li>
                <li>Se recomienda un tiempo de espera (timeout) de al menos 60 segundos al hacer solicitudes a esta API</li>
                <li>Para archivos grandes, el análisis puede llevar más tiempo</li>
            </ul>
        </div>
    </body>
    </html>
    """

# Nueva ruta para verificar la autenticación
@app.route('/api/v1/check_auth', methods=['GET'])
@require_api_key
def check_auth():
    """
    Endpoint para verificar la autenticación de la API Key
    """
    return json_response(create_json_response(
        status="success",
        data={"message": "API Key válida"}
    )), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Iniciando servidor Flask en el puerto {port}")
    app.run(host='0.0.0.0', port=port)
