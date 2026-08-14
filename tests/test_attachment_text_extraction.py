"""
HU-06: extraccion de texto de adjuntos TXT/HTML para busqueda de IOCs.

Los casos de seguridad (HTML "malicioso": script embebido, DOCTYPE con
entidad externa al estilo XXE) se prueban llamando directamente a
extract_attachment_text(), en vez de a traves del pipeline completo de
analyze_eml(): extract_body() ya incluye (comportamiento previo a esta
HU, no introducido por ella) el contenido crudo de cualquier parte
text/* del mensaje -incluyendo adjuntos- como si fuera cuerpo, sin pasar
por BeautifulSoup. Probar la funcion nueva de forma aislada es lo que
realmente verifica las garantias de seguridad de esta HU (html.parser,
sin ejecutar nada, sin resolver recursos externos); el test end-to-end
cubre el criterio de aceptacion funcional (URL de un adjunto HTML
aparece en los findings).
"""
import json
from io import BytesIO

from contract_schema import assert_matches_success_contract


def test_text_plain_attachment_is_returned_as_is():
    import app as app_module

    text = "Contacto: actor-test@ejemplo-remitente-test.com\n"
    result = app_module.extract_attachment_text("notas.txt", "text/plain", text.encode("utf-8"))
    assert result == text


def test_html_attachment_extracts_only_visible_text():
    import app as app_module

    html = (
        b"<html><body>"
        b"<p>Verifique su cuenta en "
        b'<a href="http://adjunto-html-malicioso-test.com/verificar">'
        b"http://adjunto-html-malicioso-test.com/verificar</a></p>"
        b"</body></html>"
    )
    result = app_module.extract_attachment_text("pagina.html", "text/html", html)
    assert "adjunto-html-malicioso-test.com" in result


def test_html_attachment_excludes_script_and_style_content():
    """Caso de seguridad: el texto de <script>/<style> no debe filtrarse como si fuera contenido visible."""
    import app as app_module

    html = (
        b"<html><head><style>.oculto-css-test.com { display:none; }</style></head>"
        b'<body><script>var x = "no-debe-aparecer-script-test.com";</script>'
        b"<p>Texto visible sin IOCs falsos.</p></body></html>"
    )
    result = app_module.extract_attachment_text("pagina.html", "text/html", html)
    assert "no-debe-aparecer-script-test.com" not in result
    assert "oculto-css-test.com" not in result
    assert "Texto visible sin IOCs falsos." in result


def test_html_attachment_with_xxe_style_doctype_does_not_crash_or_resolve_entity():
    """
    Caso de seguridad critico: un DOCTYPE con declaracion de entidad externa
    (estilo XXE) no debe colgar el analisis ni intentar resolver el
    recurso referenciado. html.parser (stdlib) no resuelve entidades
    externas, a diferencia de parsers XML como lxml.
    """
    import app as app_module

    html = (
        b'<!DOCTYPE html [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
        b"<html><body><p>&xxe; Texto normal.</p></body></html>"
    )
    result = app_module.extract_attachment_text("malicioso.html", "text/html", html)
    assert "root:" not in result  # nunca se resuelve el contenido de /etc/passwd
    assert "Texto normal." in result


def test_html_attachment_img_src_is_not_treated_as_visible_text():
    """No debe intentarse resolver ni incluir recursos referenciados solo en atributos (ej. <img src>), evitando SSRF."""
    import app as app_module

    html = b'<html><body><img src="http://no-debe-resolverse-test.com/x.png"></body></html>'
    result = app_module.extract_attachment_text("pagina.html", "text/html", html)
    assert "no-debe-resolverse-test.com" not in result


def test_non_text_content_type_is_skipped():
    import app as app_module

    for content_type in ["application/pdf", "application/octet-stream", "image/png", ""]:
        assert app_module.extract_attachment_text("archivo.bin", content_type, b"contenido cualquiera") == ""


def test_oversized_attachment_is_skipped():
    import app as app_module

    oversized = b"a" * (app_module.MAX_ATTACHMENT_SIZE + 1)
    assert app_module.extract_attachment_text("grande.txt", "text/plain", oversized) == ""


def test_undecodable_bytes_return_empty_string_without_crashing():
    import app as app_module

    result = app_module.extract_attachment_text("binario.txt", "text/plain", b"\xff\xfe\xfd\xfc")
    assert isinstance(result, str)


def test_empty_data_returns_empty_string():
    import app as app_module

    assert app_module.extract_attachment_text("vacio.txt", "text/plain", b"") == ""


def test_html_attachment_url_appears_in_findings_and_matches_output_contract(client, api_key, fixtures_dir):
    content = (fixtures_dir / "sample_html_attachment.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_html_attachment.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)

    network_indicators = payload["data"]["findings"]["network_indicators"]
    assert "adjunto-html-malicioso-test.com" in network_indicators["domains"]
    assert "http://adjunto-html-malicioso-test.com/verificar" in network_indicators["urls"]

    attachment_filenames = {a["filename"] for a in payload["data"]["email_metadata"]["attachments"]}
    assert {"pagina.html", "notas.txt"}.issubset(attachment_filenames)


def test_regression_existing_txt_attachment_still_works(client, api_key, fixtures_dir):
    """Regresion: el adjunto documento.txt de HU-01 sigue procesandose sin romper el contrato."""
    content = (fixtures_dir / "sample_phishing.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_phishing.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)
    assert len(payload["data"]["email_metadata"]["attachments"]) == 1
