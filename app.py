from flask import Flask, request, jsonify
import tempfile
import os
import logging
import re
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from ioc_finder import find_iocs
import json
from logging.handlers import RotatingFileHandler

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

def create_json_response(status="success", data=None, error=None):
    """
    Crea una respuesta JSON estandarizada
    """
    response = {
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.1"
    }
    
    if data is not None:
        response["data"] = data
    if error is not None:
        response["error"] = error
        
    return response

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
        return datetime.utcnow().isoformat()

    except Exception as e:
        logger.error(f"Error in parse_email_date: {str(e)}", exc_info=True)
        return datetime.utcnow().isoformat()

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
                        # Intentar múltiples codificaciones si la primera falla
                        encodings = [charset, 'utf-8', 'latin1', 'cp1252', 'ascii']
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
                try:
                    decoded = content.decode(charset)
                    body_content.append(decoded)
                except UnicodeDecodeError:
                    # Intentar con codificaciones alternativas
                    for encoding in ['utf-8', 'latin1', 'cp1252', 'ascii']:
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

def analyze_eml(eml_path):
    """
    Analiza un archivo EML y extrae IOCs
    """
    logger.info(f"Iniciando análisis del archivo EML: {eml_path}")
    try:
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

        # Combinar todo el contenido para análisis
        full_content = "\n".join(header_content + [email_body])
        logger.debug("Contenido completo preparado para análisis de IOCs")

        # Encontrar IOCs
        logger.debug("Buscando Indicadores de Compromiso (IOCs)")
        iocs = find_iocs(full_content)
        logger.debug(f"IOCs encontrados: {iocs}")

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
        dt = datetime.utcnow()
        millis = dt.microsecond // 1000
        analysis_id = f"IOC-{dt.strftime('%Y%m%d-%H%M%S')}-{millis:03d}"
        
        analysis_result = {
            "analysis_metadata": {
                "analysis_id": analysis_id,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "file_analyzed": eml_path
            },
            "email_metadata": {
                "from": str(msg.get("from", "")),
                "to": str(msg.get("to", "")),
                "subject": str(msg.get("subject", "")),
                "date": email_date,  # Usando la nueva fecha parseada
                "body_extracted": bool(email_body),
                "body": email_body
            },
            "findings": structured_iocs
        }
        
        logger.info("Análisis completado con éxito")
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error al analizar el archivo EML: {str(e)}", exc_info=True)
        raise
@app.route('/')
def index():
    return jsonify({
        "status": "success",
        "message": "PhishProtect API está en funcionamiento",
        "version": "1.1",
        "endpoints": {
            "analyze_eml": "/api/v1/analyze_eml (POST)"
        }
    })
    
@app.route('/api/v1/analyze_eml', methods=['POST'])
def analyze_eml_file():
    """
    Endpoint para analizar archivos EML
    """
    logger.info("Recibida solicitud de análisis de EML")
    try:
        if 'eml_file' not in request.files:
            logger.warning("No se ha subido ningún archivo")
            return jsonify(create_json_response(
                status="error",
                error="No file uploaded"
            )), 400
            
        file = request.files['eml_file']
        logger.debug(f"Nombre del archivo recibido: {file.filename}")
        
        if file.filename == '':
            logger.warning("No se ha seleccionado ningún archivo")
            return jsonify(create_json_response(
                status="error",
                error="No file selected"
            )), 400
            
        if not file.filename.lower().endswith('.eml'):
            logger.warning("El archivo no es un archivo EML")
            return jsonify(create_json_response(
                status="error",
                error="File must be an EML file"
            )), 400
            
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
            return jsonify(response), 200
            
        finally:
            if os.path.exists(temp_filename):
                logger.debug(f"Eliminando archivo temporal: {temp_filename}")
                os.remove(temp_filename)
                
    except Exception as e:
        logger.error(f"Error al procesar el archivo EML: {str(e)}", exc_info=True)
        return jsonify(create_json_response(
            status="error",
            error=str(e)
        )), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servidor Flask en el puerto {port}")
    app.run(host='0.0.0.0', port=port)
