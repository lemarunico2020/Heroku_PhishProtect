--- START OF FILE app.py ---

from flask import Flask, request, Response
import tempfile
import os
import logging
import re
import hashlib
from datetime import datetime, timezone
from functools import wraps
import json
from logging.handlers import RotatingFileHandler

# Importaciones para manejo de correos y EML
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, getaddresses
from email.header import decode_header, make_header

# Importaciones para análisis
from ioc_finder import find_iocs
import extract_msg  # Para archivos MSG

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
        if not API_KEY:
            logger.error("API Key no configurada en el servidor")
            return json_response(create_json_response(
                status="error",
                error="API Key not configured on server"
            )), 500
            
        request_api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not request_api_key:
            return json_response(create_json_response(
                status="error",
                error="API Key required"
            )), 401
            
        if request_api_key != API_KEY:
            return json_response(create_json_response(
                status="error",
                error="Invalid API Key"
            )), 403
            
        return f(*args, **kwargs)
    return decorated_function

def check_file_size(file, max_size_bytes=MAX_FILE_SIZE):
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > max_size_bytes:
        return False, file_size, f"El archivo excede el tamaño máximo permitido de {max_size_bytes/1024/1024:.1f} MB."
    return True, file_size, ""

def create_json_response(status="success", data=None, error=None):
    response = {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.2" # Versión actualizada
    }
    if data is not None:
        response["data"] = data
    if error is not None:
        response["error"] = error
    return response

def json_response(data, status_code=200):
    return Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        status=status_code,
        mimetype='application/json'
    )

def calculate_file_hashes(file_data):
    try:
        return {
            "md5": hashlib.md5(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "sha256": hashlib.sha256(file_data).hexdigest()
        }
    except Exception as e:
        logger.error(f"Error al calcular hashes: {str(e)}", exc_info=True)
        return {}

def get_decoded_header(msg, header_name):
    """
    Obtiene y decodifica una cabecera de correo manejando codificación MIME (RFC 2047).
    Ejemplo: =?UTF-8?B?U3ViamVjdA==?= -> Subject
    """
    value = msg.get(header_name)
    if not value:
        return ""
    
    try:
        # Si usamos policy.default, a veces ya viene decodificado, pero verificamos
        if isinstance(value, str) and "=?" in value:
            # Forzar decodificación si parece MIME
            decoded_list = decode_header(value)
            # make_header convierte la lista de pares (bytes, encoding) a string
            return str(make_header(decoded_list))
        return str(value)
    except Exception as e:
        logger.warning(f"Error decodificando cabecera {header_name}: {e}")
        return str(value)

def parse_authentication_results(msg):
    try:
        auth_results_header = msg.get('authentication-results', '')
        if not auth_results_header:
            return {"spf": "NOT_FOUND", "dkim": "NOT_FOUND", "dmarc": "NOT_FOUND"}

        auth_results_lower = str(auth_results_header).lower()

        spf_result = "NOT_FOUND"
        spf_match = re.search(r'spf\s*=\s*(pass|fail|neutral|softfail|none|temperror|permerror)', auth_results_lower)
        if spf_match: spf_result = spf_match.group(1).upper()

        dkim_result = "NOT_FOUND"
        dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|policy|temperror|permerror)', auth_results_lower)
        if dkim_match: dkim_result = dkim_match.group(1).upper()

        dmarc_result = "NOT_FOUND"
        dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)', auth_results_lower)
        if dmarc_match: dmarc_result = dmarc_match.group(1).upper()

        return {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result}
    except Exception as e:
        logger.error(f"Error parsing authentication results: {str(e)}")
        return {"spf": "ERROR", "dkim": "ERROR", "dmarc": "ERROR"}

def extract_email_headers(msg):
    """
    Extrae cabeceras adicionales del correo electrónico EML
    """
    try:
        # Usamos get_decoded_header para cabeceras que pueden tener texto libre
        return_path = str(msg.get('return-path'))
        reply_to = get_decoded_header(msg, 'reply-to')
        x_originating_ip = str(msg.get('x-originating-ip'))
        x_mailer = str(msg.get('x-mailer'))
        authentication_results = str(msg.get('authentication-results'))

        received_chain = []
        received_headers = msg.get_all('received')
        if received_headers:
            for received in received_headers:
                if received:
                    received_chain.append(str(received))

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
        return {"return_path": None, "reply_to": None, "x_originating_ip": None, "x_mailer": None, "received_chain": [], "authentication_results": None}

def extract_msg_headers(msg):
    try:
        return_path = None
        reply_to = None
        x_originating_ip = None
        x_mailer = None
        authentication_results = None
        received_chain = []

        if hasattr(msg, 'header') and msg.header:
            header_text = str(msg.header)
            
            # Patrones regex
            patterns = {
                "return_path": r'Return-Path:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)',
                "reply_to": r'Reply-To:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)',
                "x_originating_ip": r'X-Originating-IP:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)',
                "x_mailer": r'X-Mailer:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)',
                "auth_results": r'Authentication-Results:\s*(.+?)(?:\r?\n(?=[A-Z][\w-]*:)|\r?\n(?!\s)|$)'
            }

            match = re.search(patterns["return_path"], header_text, re.IGNORECASE | re.MULTILINE)
            if match: return_path = match.group(1).strip()

            match = re.search(patterns["reply_to"], header_text, re.IGNORECASE | re.MULTILINE)
            if match: 
                reply_to = match.group(1).strip()
                if re.search(r'[A-Z][\w-]*:', reply_to): reply_to = None

            match = re.search(patterns["x_originating_ip"], header_text, re.IGNORECASE | re.MULTILINE)
            if match: x_originating_ip = match.group(1).strip()

            match = re.search(patterns["x_mailer"], header_text, re.IGNORECASE | re.MULTILINE)
            if match: x_mailer = match.group(1).strip()

            match = re.search(patterns["auth_results"], header_text, re.IGNORECASE | re.MULTILINE)
            if match: authentication_results = match.group(1).strip()

            received_matches = re.findall(r'Received:\s*(.+?)(?=\r?\nReceived:|\r?\n[A-Z][\w-]*:|$)', header_text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if received_matches:
                received_chain = [r.strip() for r in received_matches]

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
        return {"return_path": None, "reply_to": None, "x_originating_ip": None, "x_mailer": None, "received_chain": [], "authentication_results": None}

def parse_email_date(msg):
    try:
        date_str = msg.get('date')
        if date_str:
            try:
                return parsedate_to_datetime(date_str).isoformat()
            except Exception:
                pass
        return datetime.now(timezone.utc).isoformat()
    except Exception as e:
        logger.error(f"Error in parse_email_date: {str(e)}")
        return datetime.now(timezone.utc).isoformat()

def extract_body(msg):
    """
    Función robusta para extraer el cuerpo del correo electrónico (EML)
    Maneja mejor los multiparts y codificaciones
    """
    body_content = []
    
    if msg.is_multipart():
        for part in msg.walk():
            # Obtener Content-Type y Content-Disposition
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Ignorar contenedores y adjuntos (queremos solo el texto visible)
            if part.get_content_maintype() == 'multipart' or "attachment" in content_disposition:
                continue

            if content_type == 'text/plain' or content_type == 'text/html':
                try:
                    # Obtener payload en bytes
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                        
                    # Limitar tamaño por parte
                    if len(payload) > MAX_CONTENT_ANALYSIS_SIZE:
                        payload = payload[:MAX_CONTENT_ANALYSIS_SIZE]

                    # Intentar obtener el charset definido
                    charset = part.get_content_charset()
                    decoded_text = None
                    
                    if charset:
                        try:
                            decoded_text = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            pass 

                    # Fallbacks de codificación comunes
                    if not decoded_text:
                        for enc in ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']:
                            try:
                                decoded_text = payload.decode(enc, errors='replace')
                                break
                            except:
                                continue
                    
                    if decoded_text:
                        body_content.append(decoded_text)
                        
                except Exception as e:
                    logger.error(f"Error extrayendo parte del cuerpo: {str(e)}")
    else:
        # Mensaje simple
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                if len(payload) > MAX_CONTENT_ANALYSIS_SIZE:
                    payload = payload[:MAX_CONTENT_ANALYSIS_SIZE]
                    
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    body_content.append(payload.decode(charset, errors='replace'))
                except:
                    body_content.append(payload.decode('utf-8', errors='replace'))
        except Exception as e:
            logger.error(f"Error extrayendo cuerpo simple: {str(e)}")

    return "\n".join(body_content)

def extract_eml_attachments(msg):
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
                
            filename = part.get_filename()
            if filename:
                try:
                    # Decodificar nombre de archivo si está en MIME
                    if "=?" in filename:
                        filename = str(make_header(decode_header(filename)))
                        
                    content_type = part.get_content_type()
                    attachment_data = part.get_payload(decode=True)
                    
                    if attachment_data:
                        attachment_size = len(attachment_data)
                        attachment_info = {
                            "filename": filename,
                            "content_type": content_type,
                            "size": attachment_size
                        }
                        
                        if attachment_size <= MAX_ATTACHMENT_SIZE:
                            hashes = calculate_file_hashes(attachment_data)
                            attachment_info["hashes"] = hashes
                        else:
                            attachment_info["hashes"] = {"info": "Too large"}
                        
                        attachments.append(attachment_info)
                except Exception as e:
                    logger.error(f"Error al procesar adjunto {filename}: {str(e)}")
    
    return attachments

def analyze_eml(eml_path):
    """
    Analiza un archivo EML y extrae IOCs
    Versión optimizada y corregida para decodificación y parseo
    """
    logger.info(f"Iniciando análisis del archivo EML: {eml_path}")
    try:
        file_size = os.path.getsize(eml_path)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"El archivo excede el tamaño máximo permitido")
        
        with open(eml_path, 'rb') as f:
            # Usar policy.default para mejor manejo moderno de EML
            msg = BytesParser(policy=policy.default).parse(f)
            
            # Decodificar cabeceras principales
            subject = get_decoded_header(msg, 'subject') or 'No subject'
            sender = get_decoded_header(msg, 'from')
            
            logger.info(f"Procesando correo con Subject: {subject}")

        # --- Extracción correcta de destinatarios ---
        recipient_addresses = set()
        recipient_domains = set()
        
        # Obtener todas las cabeceras de destinatarios
        all_recipients_headers = []
        if msg['to']: all_recipients_headers.append(str(msg['to']))
        if msg['cc']: all_recipients_headers.append(str(msg['cc']))
        if msg['bcc']: all_recipients_headers.append(str(msg['bcc']))
        
        # getaddresses parsea correctamente "Name, Surname <email>"
        for name, addr in getaddresses(all_recipients_headers):
            if addr:
                addr = addr.lower().strip()
                recipient_addresses.add(addr)
                if '@' in addr:
                    try:
                        domain = addr.split('@')[1].strip()
                        recipient_domains.add(domain)
                    except IndexError:
                        pass

        # Preparar contenido para análisis de IOCs
        header_content = []
        header_content.append(f"From: {sender}")
        header_content.append(f"Subject: {subject}")
        
        # Añadir otras cabeceras relevantes tal cual
        for header in ['received', 'x-originating-ip', 'authentication-results', 'return-path', 'reply-to']:
            vals = msg.get_all(header)
            if vals:
                for v in vals:
                    header_content.append(f"{header}: {v}")

        # Extraer cuerpo
        email_body = extract_body(msg)

        # Extraer metadatos adicionales
        email_date = parse_email_date(msg)
        auth_results = parse_authentication_results(msg)
        email_headers = extract_email_headers(msg)
        attachments = extract_eml_attachments(msg)

        # Combinar todo para buscar IOCs
        full_content = "\n".join(header_content + [email_body])
        
        if len(full_content) > MAX_CONTENT_ANALYSIS_SIZE:
            analyzed_content = full_content[:MAX_CONTENT_ANALYSIS_SIZE]
        else:
            analyzed_content = full_content

        # Búsqueda de IOCs
        logger.debug("Buscando IOCs")
        try:
            iocs = find_iocs(analyzed_content)
        except Exception as e:
            logger.error(f"Error buscando IOCs: {e}")
            iocs = {}

        # Procesar hashes de adjuntos
        attachment_md5s = set(iocs.get('md5s', set()))
        attachment_sha1s = set(iocs.get('sha1s', set()))
        attachment_sha256s = set(iocs.get('sha256s', set()))
        
        for attachment in attachments:
            if 'hashes' in attachment and isinstance(attachment['hashes'], dict) and 'info' not in attachment['hashes']:
                if 'md5' in attachment['hashes']: attachment_md5s.add(attachment['hashes']['md5'])
                if 'sha1' in attachment['hashes']: attachment_sha1s.add(attachment['hashes']['sha1'])
                if 'sha256' in attachment['hashes']: attachment_sha256s.add(attachment['hashes']['sha256'])

        # Filtrar destinatarios (Whitelisting)
        filtered_emails = set()
        for addr in iocs.get('email_addresses', set()):
            if addr.lower() not in recipient_addresses:
                filtered_emails.add(addr)

        filtered_domains = set()
        for domain in iocs.get('domains', set()):
            if domain.lower() not in recipient_domains:
                filtered_domains.add(domain)

        # Estructurar respuesta
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
                "md5_hashes": list(attachment_md5s),
                "sha1_hashes": list(attachment_sha1s),
                "sha256_hashes": list(attachment_sha256s),
                "sha512_hashes": list(iocs.get('sha512s', set())),
                "file_paths": list(iocs.get('file_paths', set()))
            },
            "system_indicators": {
                "registry_keys": list(iocs.get('registry_key_paths', set())),
                "mac_addresses": list(iocs.get('mac_addresses', set())),
                "user_agents": list(iocs.get('user_agents', set()))
            }
        }
        
        dt = datetime.now(timezone.utc)
        millis = dt.microsecond // 1000
        analysis_id = f"IOC-{dt.strftime('%Y%m%d-%H%M%S')}-{millis:03d}"
        
        return {
            "analysis_metadata": {
                "analysis_id": analysis_id,
                "analysis_timestamp": dt.isoformat(),
                "file_analyzed": eml_path,
                "file_type": "eml"
            },
            "email_metadata": {
                "from": sender,
                "to": str(msg.get("to", "")), 
                "subject": subject,
                "date": email_date,
                "body_extracted": bool(email_body),
                "body": email_body,
                "attachments": attachments,
                "authentication": auth_results
            },
            "cabeceras_email": email_headers,
            "findings": structured_iocs
        }
        
    except Exception as e:
        logger.error(f"Error al analizar el archivo EML: {str(e)}", exc_info=True)
        raise

def analyze_msg(msg_path):
    """
    Analiza un archivo MSG (Outlook) y extrae IOCs
    """
    logger.info(f"Iniciando análisis del archivo MSG: {msg_path}")
    msg = None
    try:
        file_size = os.path.getsize(msg_path)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"El archivo excede el tamaño máximo permitido")

        msg = extract_msg.openMsg(msg_path)
        logger.info(f"Procesando correo con Subject: {msg.subject}")
        
        # Extraer destinatarios
        recipient_addresses = set()
        recipient_domains = set()
        
        for recipient in msg.recipients:
            if hasattr(recipient, 'email') and recipient.email:
                addr = recipient.email.lower()
                recipient_addresses.add(addr)
                if '@' in addr:
                    recipient_domains.add(addr.split('@')[1])
        
        # Preparar contenido cabeceras
        header_content = []
        if msg.sender: header_content.append(f"From: {msg.sender}")
        if msg.subject: header_content.append(f"Subject: {msg.subject}")
        
        # Cuerpo
        email_body = msg.body
        if email_body and len(email_body) > MAX_CONTENT_ANALYSIS_SIZE:
            email_body = email_body[:MAX_CONTENT_ANALYSIS_SIZE]
        
        # Fecha
        if msg.date:
            email_date = msg.date if isinstance(msg.date, str) else msg.date.isoformat()
        else:
            email_date = datetime.now(timezone.utc).isoformat()

        # Cabeceras extra y auth
        msg_headers = extract_msg_headers(msg)
        
        # Auth results parseo manual desde header text
        auth_results = {"spf": "NOT_FOUND", "dkim": "NOT_FOUND", "dmarc": "NOT_FOUND"}
        if hasattr(msg, 'header') and msg.header:
            h_text = str(msg.header).lower()
            if 'spf=' in h_text:
                m = re.search(r'spf\s*=\s*(\w+)', h_text)
                if m: auth_results['spf'] = m.group(1).upper()
            if 'dkim=' in h_text:
                m = re.search(r'dkim\s*=\s*(\w+)', h_text)
                if m: auth_results['dkim'] = m.group(1).upper()
            if 'dmarc=' in h_text:
                m = re.search(r'dmarc\s*=\s*(\w+)', h_text)
                if m: auth_results['dmarc'] = m.group(1).upper()

        # Adjuntos
        attachments_info = []
        for attachment in msg.attachments:
            try:
                if hasattr(attachment, 'longFilename') and attachment.longFilename:
                    data = getattr(attachment, 'data', None)
                    if data:
                        size = len(data)
                        info = {"filename": attachment.longFilename, "size": size}
                        if size <= MAX_ATTACHMENT_SIZE:
                            info["hashes"] = calculate_file_hashes(data)
                        else:
                            info["hashes"] = {"info": "Too large"}
                        attachments_info.append(info)
            except Exception as e:
                logger.error(f"Error adjunto MSG: {e}")

        # Contenido completo para IOCs
        add_headers = []
        for k, v in msg_headers.items():
            if isinstance(v, list): add_headers.extend(v)
            elif v: add_headers.append(f"{k}: {v}")

        full_content = "\n".join(header_content + add_headers + [email_body if email_body else ""])
        if len(full_content) > MAX_CONTENT_ANALYSIS_SIZE:
            analyzed_content = full_content[:MAX_CONTENT_ANALYSIS_SIZE]
        else:
            analyzed_content = full_content

        # IOC Finder
        try:
            iocs = find_iocs(analyzed_content)
        except Exception:
            iocs = {}

        # Procesar hashes
        attachment_md5s = set(iocs.get('md5s', set()))
        attachment_sha1s = set(iocs.get('sha1s', set()))
        attachment_sha256s = set(iocs.get('sha256s', set()))
        
        for att in attachments_info:
            if 'hashes' in att and 'md5' in att['hashes']:
                attachment_md5s.add(att['hashes']['md5'])
                attachment_sha1s.add(att['hashes']['sha1'])
                attachment_sha256s.add(att['hashes']['sha256'])

        # Filtrar destinatarios
        filtered_emails = set(e for e in iocs.get('email_addresses', []) if e.lower() not in recipient_addresses)
        filtered_domains = set(d for d in iocs.get('domains', []) if d.lower() not in recipient_domains)

        structured_iocs = {
            "network_indicators": {
                "domains": list(filtered_domains),
                "ipv4": list(iocs.get('ipv4s', [])),
                "ipv6": list(iocs.get('ipv6s', [])),
                "urls": list(iocs.get('urls', [])),
                "email_addresses": list(filtered_emails),
                "asns": list(iocs.get('asns', [])),
                "cidr_ranges": list(iocs.get('cidr_ranges', []))
            },
            "file_indicators": {
                "md5_hashes": list(attachment_md5s),
                "sha1_hashes": list(attachment_sha1s),
                "sha256_hashes": list(attachment_sha256s),
                "sha512_hashes": list(iocs.get('sha512s', [])),
                "file_paths": list(iocs.get('file_paths', []))
            },
            "system_indicators": {
                "registry_keys": list(iocs.get('registry_key_paths', [])),
                "mac_addresses": list(iocs.get('mac_addresses', [])),
                "user_agents": list(iocs.get('user_agents', []))
            }
        }

        dt = datetime.now(timezone.utc)
        millis = dt.microsecond // 1000
        analysis_id = f"IOC-{dt.strftime('%Y%m%d-%H%M%S')}-{millis:03d}"

        return {
            "analysis_metadata": {
                "analysis_id": analysis_id,
                "analysis_timestamp": dt.isoformat(),
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
                "authentication": auth_results
            },
            "cabeceras_email": msg_headers,
            "findings": structured_iocs
        }

    except Exception as e:
        logger.error(f"Error al analizar el archivo MSG: {str(e)}", exc_info=True)
        raise
    finally:
        if msg is not None:
            try:
                msg.close()
            except Exception:
                pass

@app.route('/api/v1/analyze_email', methods=['POST'])
@require_api_key
def analyze_email_file():
    try:
        file = None
        file_field_name = None
        
        for field in ['email_file', 'eml_file', 'msg_file', 'file']:
            if field in request.files and request.files[field].filename != '':
                file = request.files[field]
                file_field_name = field
                break
        
        if not file:
            return json_response(create_json_response(status="error", error="No file uploaded"), 400)
        
        size_ok, file_size, error_message = check_file_size(file, MAX_FILE_SIZE)
        if not size_ok:
            return json_response(create_json_response(status="error", error=error_message), 413)
            
        file_extension = file.filename.lower().split('.')[-1] if '.' in file.filename else ''
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as temp_file:
            file.save(temp_file.name)
            temp_filename = temp_file.name
            
            # Detectar tipo si no está claro
            if file_extension not in ['eml', 'msg']:
                try:
                    with open(temp_filename, 'rb') as f:
                        BytesParser(policy=policy.default).parse(f)
                        file_extension = 'eml'
                except:
                    try:
                        t = extract_msg.openMsg(temp_filename)
                        t.close()
                        file_extension = 'msg'
                    except:
                        os.remove(temp_filename)
                        return json_response(create_json_response(status="error", error="Unknown file type"), 400)

        try:
            if file_extension == 'eml':
                results = analyze_eml(temp_filename)
            else:
                results = analyze_msg(temp_filename)
                
            return json_response(create_json_response(status="success", data=results), 200)
            
        except ValueError as ve:
            return json_response(create_json_response(status="error", error=str(ve)), 413)
        except Exception as e:
            return json_response(create_json_response(status="error", error=str(e)), 500)
        finally:
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
                
    except Exception as e:
        logger.error(f"Error procesando solicitud: {e}", exc_info=True)
        return json_response(create_json_response(status="error", error=str(e)), 500)

@app.route('/api/v1/analyze_eml', methods=['POST'])
@require_api_key
def analyze_eml_file():
    # Wrapper simple para compatibilidad hacia atrás
    if 'eml_file' not in request.files:
         return json_response(create_json_response(status="error", error="No eml_file uploaded"), 400)
    return analyze_email_file()

@app.route('/api/v1/analyze_msg', methods=['POST'])
@require_api_key
def analyze_msg_file():
    # Wrapper simple para compatibilidad hacia atrás
    if 'msg_file' not in request.files:
         return json_response(create_json_response(status="error", error="No msg_file uploaded"), 400)
    return analyze_email_file()

@app.route('/api/v1/check_auth', methods=['GET'])
@require_api_key
def check_auth():
    return json_response(create_json_response(status="success", data={"message": "API Key válida"}), 200)

@app.route('/', methods=['GET'])
def home():
    return """
    <html><body>
        <h1>PhishProtect API v1.2</h1>
        <p>Servicio de análisis de correos EML y MSG.</p>
        <p>Endpoints: /api/v1/analyze_email (POST)</p>
    </body></html>
    """

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Iniciando servidor Flask en el puerto {port}")
    app.run(host='0.0.0.0', port=port)
