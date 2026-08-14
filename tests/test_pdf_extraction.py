"""
HU-07 (stretch): extraccion de texto de adjuntos PDF.

Los parsers de PDF son una superficie de ataque historica (decompression
bombs, streams malformados que consumen memoria/CPU sin limite), por eso
esta HU exige timeout duro, limite de paginas procesadas y que un PDF
corrupto/malformado nunca tumbe el analisis completo del correo. Los PDFs
sinteticos se generan a mano (ver pdf_builder.py) sin depender de una
libreria de autoria externa.
"""
import json
from io import BytesIO

from contract_schema import assert_matches_success_contract
from pdf_builder import build_pdf


def test_pdf_attachment_text_is_extracted():
    import app as app_module

    pdf_bytes = build_pdf(["Contacto: actor-pdf-test@ejemplo-remitente-test.com"])
    result = app_module.extract_attachment_text("factura.pdf", "application/pdf", pdf_bytes)
    assert "actor-pdf-test@ejemplo-remitente-test.com" in result


def test_pdf_page_limit_is_enforced():
    """Solo se procesan las primeras MAX_PDF_PAGES_PROCESSED paginas (20 por defecto)."""
    import app as app_module

    page_texts = [f"marcador-pagina-{i}-test.com" for i in range(25)]
    pdf_bytes = build_pdf(page_texts)
    result = app_module.extract_attachment_text("grande.pdf", "application/pdf", pdf_bytes)

    assert "marcador-pagina-0-test.com" in result
    assert "marcador-pagina-19-test.com" in result
    assert "marcador-pagina-20-test.com" not in result
    assert "marcador-pagina-24-test.com" not in result


def test_corrupt_pdf_returns_empty_string_without_crashing():
    import app as app_module

    result = app_module.extract_attachment_text("corrupto.pdf", "application/pdf", b"%PDF-1.4 esto no es un PDF valido")
    assert result == ""


def test_non_pdf_binary_labeled_as_pdf_does_not_crash():
    """Defensa en profundidad: bytes arbitrarios con content_type application/pdf no deben tumbar el analisis."""
    import app as app_module

    result = app_module.extract_attachment_text("falso.pdf", "application/pdf", b"\x00\x01\x02binario-arbitrario\xff\xfe")
    assert result == ""


def test_oversized_pdf_attachment_is_skipped():
    import app as app_module

    oversized = b"a" * (app_module.MAX_ATTACHMENT_SIZE + 1)
    assert app_module.extract_attachment_text("grande.pdf", "application/pdf", oversized) == ""


def test_empty_pdf_data_returns_empty_string():
    import app as app_module

    assert app_module.extract_attachment_text("vacio.pdf", "application/pdf", b"") == ""


def test_pdf_attachment_url_appears_in_findings_and_matches_output_contract(client, api_key, fixtures_dir):
    content = (fixtures_dir / "sample_pdf_attachment.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_pdf_attachment.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)

    network_indicators = payload["data"]["findings"]["network_indicators"]
    assert "adjunto-pdf-malicioso-test.com" in network_indicators["domains"]
    assert "http://adjunto-pdf-malicioso-test.com/pago" in network_indicators["urls"]
    assert "actor-pdf-test@ejemplo-remitente-test.com" in network_indicators["email_addresses"]

    attachment = payload["data"]["email_metadata"]["attachments"][0]
    assert attachment["filename"] == "factura.pdf"
    assert attachment["content_type"] == "application/pdf"


def test_corrupt_pdf_attachment_does_not_break_full_email_analysis(client, api_key):
    """
    Criterio critico de HU-07: si la extraccion falla, el analisis del
    correo completo continua sin bloquear (no se cae la request).
    """
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "soporte@ejemplo-remitente-test.com"
    msg["To"] = "destinatario@empresa-cliente-test.com"
    msg["Subject"] = "Adjunto PDF corrupto"
    msg.set_content("Cuerpo de prueba con un adjunto PDF corrupto.")
    msg.add_attachment(
        b"%PDF-1.4 contenido corrupto que no es un PDF valido",
        maintype="application",
        subtype="pdf",
        filename="corrupto.pdf",
    )

    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(msg.as_bytes()), "corrupto.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)
    assert payload["data"]["email_metadata"]["attachments"][0]["filename"] == "corrupto.pdf"
