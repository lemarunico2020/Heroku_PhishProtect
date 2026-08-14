"""
Extraccion de texto de adjuntos (TXT/HTML/PDF) para busqueda de IOCs,
compartida entre parsers/eml.py y parsers/msg.py (HU-06/HU-07, movido
a modulo propio en HU-12).
"""
import signal
from io import BytesIO

from bs4 import BeautifulSoup
from pypdf import PdfReader

from settings import MAX_ATTACHMENT_SIZE, logger

TEXT_ATTACHMENT_CONTENT_TYPES = {'text/plain', 'text/html'}
PDF_ATTACHMENT_CONTENT_TYPE = 'application/pdf'
ATTACHMENT_HTML_PARSE_TIMEOUT_SECONDS = 5
ATTACHMENT_PDF_PARSE_TIMEOUT_SECONDS = 5
MAX_PDF_PAGES_PROCESSED = 20


def _run_with_timeout(func, timeout_seconds, timeout_message):
    """
    Ejecuta func() con un timeout duro via signal.alarm cuando esta
    disponible (workers gunicorn sync, un solo hilo por proceso). En
    Windows, o si se invoca fuera del hilo principal (signal.alarm solo
    funciona ahi), se degrada a ejecutar sin timeout duro, mitigado
    igualmente por MAX_ATTACHMENT_SIZE (y, para PDF, MAX_PDF_PAGES_PROCESSED).
    """
    if hasattr(signal, 'SIGALRM'):
        try:
            def _handle_timeout(signum, frame):
                raise TimeoutError(timeout_message)
            previous_handler = signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(timeout_seconds)
            try:
                return func()
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous_handler)
        except ValueError:
            logger.debug("signal.alarm no disponible en este hilo, ejecutando sin timeout duro")
            return func()
    return func()


def _extract_html_text_with_timeout(html_content, timeout_seconds=ATTACHMENT_HTML_PARSE_TIMEOUT_SECONDS):
    """
    Extrae el texto visible de HTML con BeautifulSoup usando el parser
    html.parser (stdlib, sin resolucion de entidades externas: evita
    XXE/billion-laughs). No renderiza el HTML (sin JS, sin resolver
    recursos externos como <img src=...>, evitando SSRF).
    """
    return _run_with_timeout(
        lambda: BeautifulSoup(html_content, "html.parser").get_text(),
        timeout_seconds,
        "Tiempo de parseo de adjunto HTML excedido"
    )


def _read_pdf_text(data):
    reader = PdfReader(BytesIO(data))
    texts = []
    for page in reader.pages[:MAX_PDF_PAGES_PROCESSED]:
        page_text = page.extract_text()
        if page_text:
            texts.append(page_text)
    return "\n".join(texts)


def _extract_pdf_text_with_timeout(data, timeout_seconds=ATTACHMENT_PDF_PARSE_TIMEOUT_SECONDS):
    """
    Extrae texto de un PDF con pypdf, limitado a las primeras
    MAX_PDF_PAGES_PROCESSED paginas. Los parsers de PDF son una
    superficie de ataque historica (decompression bombs, streams
    malformados que consumen memoria/CPU sin limite); se mitiga con
    timeout duro (ver _run_with_timeout) y el limite de paginas.
    """
    return _run_with_timeout(
        lambda: _read_pdf_text(data),
        timeout_seconds,
        "Tiempo de parseo de adjunto PDF excedido"
    )


def extract_attachment_text(filename, content_type, data):
    """
    Extrae el texto de un adjunto de texto plano, HTML o PDF para incluirlo
    en el contenido analizado en busca de IOCs (HU-06/HU-07). Solo procesa
    text/plain, text/html y application/pdf, por debajo de
    MAX_ATTACHMENT_SIZE; cualquier otro tipo (binarios, ejecutables) se
    ignora sin intentar decodificarlo. Cualquier error (incluye PDFs
    corruptos, cifrados o que excedan el timeout) se captura y devuelve
    texto vacio, sin tumbar el analisis del correo completo.
    """
    if not data or len(data) > MAX_ATTACHMENT_SIZE:
        return ""

    if content_type == PDF_ATTACHMENT_CONTENT_TYPE:
        try:
            return _extract_pdf_text_with_timeout(data)
        except Exception as e:
            logger.warning(f"Error al extraer texto del adjunto PDF {filename}: {str(e)}")
            return ""

    if content_type not in TEXT_ATTACHMENT_CONTENT_TYPES:
        return ""

    decoded = None
    for encoding in ['utf-8', 'latin1', 'cp1252', 'ascii', 'iso-8859-1']:
        try:
            decoded = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue

    if decoded is None:
        logger.warning(f"No se pudo decodificar el adjunto de texto: {filename}")
        return ""

    if content_type == 'text/plain':
        return decoded

    try:
        return _extract_html_text_with_timeout(decoded)
    except Exception as e:
        logger.warning(f"Error al extraer texto del adjunto HTML {filename}: {str(e)}")
        return ""
