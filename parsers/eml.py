"""
Parseo y analisis de archivos EML (HU-12: extraido de app.py).
"""
import os
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

import settings
from settings import logger
from iocs import (
    calculate_file_hashes,
    fang_content_safe,
    filter_recipient_iocs,
    find_iocs_safe,
    process_iocs_with_attachments,
    structure_iocs,
    build_analysis_result,
)
from parsers.attachments import extract_attachment_text


def parse_authentication_results(msg):
    """
    Parsea las cabeceras de autenticación (Authentication-Results, ARC-Authentication-Results, DKIM-Signature)
    y extrae los resultados de SPF, DKIM y DMARC
    """
    try:
        spf_result = "NOT_FOUND"
        dkim_result = "NOT_FOUND"
        dmarc_result = "NOT_FOUND"

        # Buscar en Authentication-Results estándar
        auth_results_header = msg.get('authentication-results', '')

        # Si no existe, buscar en ARC-Authentication-Results (puede haber múltiples)
        if not auth_results_header:
            arc_auth_results = msg.get_all('arc-authentication-results')
            if arc_auth_results:
                # Combinar todas las cabeceras ARC-Authentication-Results
                auth_results_header = ' '.join([str(h) for h in arc_auth_results if h])
                logger.debug(f"Usando ARC-Authentication-Results: {auth_results_header}")

        if auth_results_header:
            logger.debug(f"Authentication-Results header: {auth_results_header}")
            auth_results_lower = auth_results_header.lower()

            # Extraer resultado SPF
            spf_match = re.search(r'spf\s*=\s*(pass|fail|neutral|softfail|none|temperror|permerror)', auth_results_lower)
            if spf_match:
                spf_result = spf_match.group(1).upper()

            # Extraer resultado DKIM
            dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|policy|temperror|permerror)', auth_results_lower)
            if dkim_match:
                dkim_result = dkim_match.group(1).upper()

            # Extraer resultado DMARC
            dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)', auth_results_lower)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1).upper()

        # Si aún no encontramos DKIM, buscar en DKIM-Signature header
        if dkim_result == "NOT_FOUND":
            dkim_signature = msg.get('dkim-signature')
            if dkim_signature:
                dkim_result = "SIGNATURE_PRESENT"
                logger.debug("DKIM-Signature encontrada")

        logger.info(f"Resultados de autenticación - SPF: {spf_result}, DKIM: {dkim_result}, DMARC: {dmarc_result}")

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
        # Logging de todas las cabeceras disponibles para diagnóstico
        all_headers = list(msg.keys())
        logger.debug(f"Cabeceras disponibles en EML: {all_headers}")

        # Extraer cabeceras estándar
        return_path = msg.get('return-path', None)
        reply_to = msg.get('reply-to', None)
        x_originating_ip = msg.get('x-originating-ip', None)
        x_mailer = msg.get('x-mailer', None)

        # Extraer Authentication-Results (probar ambas variantes)
        authentication_results = msg.get('authentication-results', None)

        # Si no existe, buscar en ARC-Authentication-Results
        if not authentication_results:
            arc_auth_results = msg.get_all('arc-authentication-results')
            if arc_auth_results:
                authentication_results = ' | '.join([str(h) for h in arc_auth_results if h])

        # Extraer cadena de Received headers
        received_chain = []
        received_headers = msg.get_all('received')
        if received_headers:
            for received in received_headers:
                if received:
                    received_chain.append(str(received))

        logger.debug(f"Cabeceras extraídas - Return-Path: {return_path}, Reply-To: {reply_to}, X-Originating-IP: {x_originating_ip}, Received: {len(received_chain)}, Auth: {'Sí' if authentication_results else 'No'}")

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
                        if len(content) > settings.MAX_CONTENT_ANALYSIS_SIZE:
                            logger.warning(f"Contenido de parte muy grande ({len(content)} bytes), limitando a {settings.MAX_CONTENT_ANALYSIS_SIZE} bytes")
                            content = content[:settings.MAX_CONTENT_ANALYSIS_SIZE]

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
                if len(content) > settings.MAX_CONTENT_ANALYSIS_SIZE:
                    logger.warning(f"Contenido de mensaje simple muy grande ({len(content)} bytes), limitando a {settings.MAX_CONTENT_ANALYSIS_SIZE} bytes")
                    content = content[:settings.MAX_CONTENT_ANALYSIS_SIZE]

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
    Extrae archivos adjuntos de un mensaje EML, calcula sus hashes y, para
    adjuntos de texto plano/HTML/PDF, extrae su texto visible (HU-06/HU-07).
    Con optimizaciones para manejar adjuntos grandes.

    Devuelve (attachments, attachment_texts): metadatos para la respuesta
    JSON y una lista separada de textos extraidos para alimentar la
    busqueda de IOCs.
    """
    attachments = []
    attachment_texts = []

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

                        if attachment_size <= settings.MAX_ATTACHMENT_SIZE:
                            # Calcular hashes
                            hashes = calculate_file_hashes(attachment_data)
                            attachment_info["hashes"] = hashes
                            extracted_text = extract_attachment_text(filename, content_type, attachment_data)
                            if extracted_text:
                                attachment_texts.append(extracted_text)
                        else:
                            logger.warning(f"Adjunto demasiado grande para calcular hashes: {filename}, tamaño: {attachment_size} bytes")
                            attachment_info["hashes"] = {
                                "info": "Adjunto demasiado grande para calcular hashes"
                            }

                        attachments.append(attachment_info)
                        logger.debug(f"Adjunto procesado: {filename}, tamaño: {attachment_size} bytes")
                except Exception as e:
                    logger.error(f"Error al procesar adjunto {filename}: {str(e)}", exc_info=True)

    return attachments, attachment_texts


def analyze_eml(eml_path):
    """
    Analiza un archivo EML y extrae IOCs
    """
    logger.info(f"Iniciando análisis de EML: {eml_path}")
    try:
        if os.path.getsize(eml_path) > settings.MAX_FILE_SIZE:
            raise ValueError(f"El archivo excede el tamaño máximo permitido de {settings.MAX_FILE_SIZE/1024/1024:.1f} MB")

        with open(eml_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        logger.info(f"Procesando: {msg.get('subject', 'No subject')}")

        # Extraer direcciones y dominios del destinatario
        recipient_addresses, recipient_domains = set(), set()
        for header in ['to', 'cc', 'bcc']:
            if msg[header]:
                for addr in str(msg[header]).split(','):
                    addr = addr.strip().lower()
                    recipient_addresses.add(addr)
                    if '@' in addr:
                        recipient_domains.add(addr.split('@')[1].strip('>'))

        # Extraer datos del email
        email_body = extract_body(msg)
        if not email_body:
            logger.warning("No se pudo extraer el cuerpo del correo")

        email_date = parse_email_date(msg)
        auth_results = parse_authentication_results(msg)
        email_headers = extract_email_headers(msg)
        attachments, attachment_texts = extract_eml_attachments(msg)
        logger.debug(f"Se encontraron {len(attachments)} adjuntos")

        # Preparar contenido para análisis de IOCs
        header_content = [str(msg[h]) for h in ['from', 'subject', 'received', 'x-originating-ip', 'authentication-results'] if msg[h]]
        additional_headers = []
        for key, prefix in [('return_path', 'Return-Path'), ('reply_to', 'Reply-To'),
                           ('x_originating_ip', 'X-Originating-IP'), ('x_mailer', 'X-Mailer'),
                           ('authentication_results', 'Authentication-Results')]:
            if email_headers.get(key):
                additional_headers.append(f"{prefix}: {email_headers[key]}")
        if email_headers.get('received_chain'):
            additional_headers.extend(email_headers['received_chain'])

        full_content = "\n".join(header_content + additional_headers + [email_body] + attachment_texts)
        analyzed_content = full_content[:settings.MAX_CONTENT_ANALYSIS_SIZE] if len(full_content) > settings.MAX_CONTENT_ANALYSIS_SIZE else full_content
        analyzed_content = fang_content_safe(analyzed_content)

        # Buscar IOCs y procesar
        iocs = find_iocs_safe(analyzed_content)
        iocs = process_iocs_with_attachments(iocs, attachments)
        filtered_emails, filtered_domains = filter_recipient_iocs(
            iocs, recipient_addresses, recipient_domains, settings.ALLOWLIST_EMAILS, settings.ALLOWLIST_DOMAINS)
        structured_iocs = structure_iocs(iocs, filtered_emails, filtered_domains)

        # Construir resultado
        analysis_result = build_analysis_result(
            eml_path, "eml",
            str(msg.get("from", "")),
            str(msg.get("to", "")),
            str(msg.get("subject", "")),
            email_date, email_body, attachments,
            auth_results, email_headers, structured_iocs
        )

        logger.info("Análisis completado con éxito")
        return analysis_result

    except Exception as e:
        logger.error(f"Error al analizar el archivo EML: {str(e)}", exc_info=True)
        raise
