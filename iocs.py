"""
Busqueda, filtrado y estructuracion de IOCs, mas el ensamblado del
resultado final del analisis (HU-12).
"""
import hashlib
import re
import ipaddress
from datetime import datetime, timezone

from ioc_finder import find_iocs
import ioc_fanger

from settings import logger


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


def fang_content_safe(content):
    """
    Revierte IOCs defangueados (hxxp://, dominio[.]com, actor[at]dominio.com)
    a su forma normal antes de la busqueda de IOCs. Se llama DESPUES de
    truncar el contenido a MAX_CONTENT_ANALYSIS_SIZE (mitigacion de ReDoS
    sobre payloads de tamano arbitrario).
    """
    try:
        return ioc_fanger.fang(content)
    except Exception as e:
        logger.error(f"Error al aplicar de-fanging de IOCs: {str(e)}", exc_info=True)
        return content


def find_iocs_safe(content):
    """
    Busca IOCs con manejo de errores mejorado
    """
    try:
        return find_iocs(content)
    except Exception as e:
        logger.error(f"Error durante la búsqueda de IOCs: {str(e)}", exc_info=True)
        return {
            'domains': set(), 'email_addresses': set(), 'ipv4s': set(),
            'ipv6s': set(), 'urls': set(), 'asns': set(), 'cidr_ranges': set(),
            'md5s': set(), 'sha1s': set(), 'sha256s': set(), 'sha512s': set(),
            'file_paths': set(), 'registry_key_paths': set(),
            'mac_addresses': set(), 'user_agents': set()
        }


def process_iocs_with_attachments(iocs, attachments):
    """
    Agrega hashes de adjuntos a los IOCs encontrados
    """
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

    iocs['md5s'] = attachment_md5s
    iocs['sha1s'] = attachment_sha1s
    iocs['sha256s'] = attachment_sha256s
    return iocs


def filter_recipient_iocs(iocs, recipient_addresses, recipient_domains,
                          allowlist_emails=None, allowlist_domains=None):
    """
    Filtra direcciones de email y dominios que pertenecen a destinatarios
    o que estan en la allowlist configurable (config/allowlist_*.txt, HU-03)
    """
    excluded_addresses = recipient_addresses | (allowlist_emails or set())
    excluded_domains = recipient_domains | (allowlist_domains or set())
    filtered_emails = set(addr for addr in iocs.get('email_addresses', set())
                        if addr.lower() not in excluded_addresses)
    filtered_domains = set(domain for domain in iocs.get('domains', set())
                         if domain.lower() not in excluded_domains)
    return filtered_emails, filtered_domains


def structure_iocs(iocs, filtered_emails, filtered_domains):
    """
    Estructura los IOCs en el formato de respuesta
    """
    return {
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


# Limite de lineas de received_chain a inspeccionar (mitigacion adicional
# de costo de regex sobre cadenas Received anomalamente largas).
MAX_RECEIVED_LINES_PROCESSED = 50

_IPV4_CANDIDATE_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_CANDIDATE_RE = re.compile(r'\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b')


def guess_originating_ip(received_chain):
    """
    Recorre received_chain de atras hacia adelante (del salto mas antiguo,
    mas cercano al origen, hacia el mas reciente) y devuelve como string la
    primera IP publica valida encontrada, o None si no hay ninguna.

    Cada candidato se valida con ipaddress (stdlib) antes de aceptarlo, para
    no propagar strings mal formados como si fueran IOCs validos, y se
    descartan rangos privados/reservados/loopback/link-local/multicast
    (incluye RFC1918 y los rangos de documentacion RFC5737/RFC3849, que
    ipaddress ya clasifica como no publicos). is_global no excluye
    multicast por si solo (ej. 224.0.0.1 o ff02::1 dan is_global=True),
    por lo que se descarta explicitamente con is_multicast.
    """
    lines_to_check = list(reversed(received_chain))[:MAX_RECEIVED_LINES_PROCESSED]
    for received in lines_to_check:
        candidates = _IPV4_CANDIDATE_RE.findall(received) + _IPV6_CANDIDATE_RE.findall(received)
        for candidate in candidates:
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip_obj.is_global and not ip_obj.is_multicast:
                return str(ip_obj)
    return None


def build_analysis_result(file_path, file_type, email_from, email_to, subject, email_date,
                         email_body, attachments, auth_results, email_headers, structured_iocs):
    """
    Construye el resultado final del análisis
    """
    dt = datetime.now(timezone.utc)
    millis = dt.microsecond // 1000
    analysis_id = f"IOC-{dt.strftime('%Y%m%d-%H%M%S')}-{millis:03d}"

    return {
        "analysis_metadata": {
            "analysis_id": analysis_id,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "file_analyzed": file_path,
            "file_type": file_type
        },
        "email_metadata": {
            "from": email_from,
            "to": email_to,
            "subject": subject,
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
            "authentication_results": email_headers["authentication_results"],
            "originating_ip_guess": guess_originating_ip(email_headers["received_chain"])
        },
        "findings": structured_iocs
    }
