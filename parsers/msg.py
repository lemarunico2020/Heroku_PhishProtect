"""
Parseo y analisis de archivos MSG (Outlook) (HU-12: extraido de app.py).
"""
import os
import re
import mimetypes
from datetime import datetime, timezone

import extract_msg  # Importación para archivos MSG

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


def extract_msg_attachments(msg):
    """
    Extrae archivos adjuntos de un mensaje MSG, calcula sus hashes y, para
    adjuntos de texto plano/HTML/PDF, extrae su texto visible (HU-06/HU-07).

    Devuelve (attachments_info, attachment_texts), igual que
    extract_eml_attachments.
    """
    attachments_info = []
    attachment_texts = []
    for attachment in msg.attachments:
        try:
            if hasattr(attachment, 'longFilename') and attachment.longFilename and hasattr(attachment, 'data') and attachment.data:
                attachment_size = len(attachment.data)
                attachment_info = {"filename": attachment.longFilename, "size": attachment_size}

                if attachment_size <= settings.MAX_ATTACHMENT_SIZE:
                    attachment_info["hashes"] = calculate_file_hashes(attachment.data)
                    content_type = getattr(attachment, 'mimetype', None)
                    if not content_type:
                        guessed_type, _ = mimetypes.guess_type(attachment.longFilename)
                        content_type = guessed_type or ''
                    extracted_text = extract_attachment_text(attachment.longFilename, content_type, attachment.data)
                    if extracted_text:
                        attachment_texts.append(extracted_text)
                else:
                    logger.warning(f"Adjunto muy grande para hashes: {attachment.longFilename}")
                    attachment_info["hashes"] = {"info": "Adjunto demasiado grande para calcular hashes"}

                attachments_info.append(attachment_info)
        except Exception as e:
            logger.error(f"Error procesando adjunto MSG: {str(e)}", exc_info=True)
    return attachments_info, attachment_texts


def parse_msg_authentication(msg):
    """
    Parsea resultados de autenticación desde cabeceras MSG
    """
    auth_results = {"spf": "NOT_FOUND", "dkim": "NOT_FOUND", "dmarc": "NOT_FOUND"}
    try:
        if hasattr(msg, 'header') and msg.header:
            header_text = str(msg.header).lower()
            for key, pattern in [('spf', r'spf\s*=\s*(pass|fail|neutral|softfail|none|temperror|permerror)'),
                                ('dkim', r'dkim\s*=\s*(pass|fail|none|neutral|policy|temperror|permerror)'),
                                ('dmarc', r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)')]:
                match = re.search(pattern, header_text)
                if match:
                    auth_results[key] = match.group(1).upper()
    except Exception as e:
        logger.warning(f"Error parseando autenticación MSG: {str(e)}")
    return auth_results


def analyze_msg(msg_path):
    """
    Analiza un archivo MSG (Outlook) y extrae IOCs
    """
    logger.info(f"Iniciando análisis de MSG: {msg_path}")
    msg = None
    try:
        if os.path.getsize(msg_path) > settings.MAX_FILE_SIZE:
            raise ValueError(f"El archivo excede el tamaño máximo permitido de {settings.MAX_FILE_SIZE/1024/1024:.1f} MB")

        msg = extract_msg.openMsg(msg_path)
        logger.info(f"Procesando: {msg.subject}")

        # Extraer direcciones y dominios del destinatario
        recipient_addresses, recipient_domains = set(), set()
        for recipient in msg.recipients:
            if hasattr(recipient, 'email') and recipient.email:
                addr = recipient.email.lower()
                recipient_addresses.add(addr)
                if '@' in addr:
                    recipient_domains.add(addr.split('@')[1])

        # Extraer datos del email
        email_body = msg.body
        if email_body and len(email_body) > settings.MAX_CONTENT_ANALYSIS_SIZE:
            logger.warning(f"Cuerpo MSG muy grande, limitando tamaño")
            email_body = email_body[:settings.MAX_CONTENT_ANALYSIS_SIZE]
        if not email_body:
            logger.warning("No se pudo extraer el cuerpo del correo")

        # Obtener fecha
        email_date = msg.date.isoformat() if hasattr(msg.date, 'isoformat') else str(msg.date) if msg.date else datetime.now(timezone.utc).isoformat()

        msg_headers = extract_msg_headers(msg)
        auth_results = parse_msg_authentication(msg)
        attachments_info, attachment_texts = extract_msg_attachments(msg)
        logger.debug(f"Se encontraron {len(attachments_info)} adjuntos")

        # Preparar contenido para análisis de IOCs
        header_content = []
        if msg.sender:
            header_content.append(f"From: {msg.sender}")
        if msg.subject:
            header_content.append(f"Subject: {msg.subject}")

        additional_headers = []
        for key, prefix in [('return_path', 'Return-Path'), ('reply_to', 'Reply-To'),
                           ('x_originating_ip', 'X-Originating-IP'), ('x_mailer', 'X-Mailer'),
                           ('authentication_results', 'Authentication-Results')]:
            if msg_headers.get(key):
                additional_headers.append(f"{prefix}: {msg_headers[key]}")
        if msg_headers.get('received_chain'):
            additional_headers.extend(msg_headers['received_chain'])

        full_content = "\n".join(header_content + additional_headers + ([email_body] if email_body else []) + attachment_texts)
        analyzed_content = full_content[:settings.MAX_CONTENT_ANALYSIS_SIZE] if len(full_content) > settings.MAX_CONTENT_ANALYSIS_SIZE else full_content
        analyzed_content = fang_content_safe(analyzed_content)

        # Buscar IOCs y procesar
        iocs = find_iocs_safe(analyzed_content)
        iocs = process_iocs_with_attachments(iocs, attachments_info)
        filtered_emails, filtered_domains = filter_recipient_iocs(
            iocs, recipient_addresses, recipient_domains, settings.ALLOWLIST_EMAILS, settings.ALLOWLIST_DOMAINS)
        structured_iocs = structure_iocs(iocs, filtered_emails, filtered_domains)

        # Construir resultado
        analysis_result = build_analysis_result(
            msg_path, "msg",
            msg.sender if msg.sender else "",
            "; ".join([r.email for r in msg.recipients if hasattr(r, 'email') and r.email]),
            msg.subject if msg.subject else "",
            email_date, email_body, attachments_info,
            auth_results, msg_headers, structured_iocs
        )

        logger.info("Análisis completado con éxito")
        return analysis_result

    except Exception as e:
        logger.error(f"Error al analizar el archivo MSG: {str(e)}", exc_info=True)
        raise
    finally:
        if msg is not None:
            try:
                msg.close()
            except Exception as e:
                logger.warning(f"Error al cerrar MSG: {str(e)}")
