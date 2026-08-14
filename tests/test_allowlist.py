"""
HU-03: allowlist configurable de dominios y correos.

Valida que los dominios/correos presentes en la allowlist configurada
(config/allowlist_domains.txt, config/allowlist_emails.txt) nunca
aparezcan como IOC en la respuesta, que la ausencia de esos archivos no
rompa el servicio, y que un archivo corrupto/no UTF-8 degrade a
allowlist vacía en vez de tumbar el proceso de carga.

Nota (HU-12): load_allowlist/ALLOWLIST_DOMAINS/ALLOWLIST_EMAILS viven en
settings.py desde el refactor a modulos; se importa settings
directamente (no app) para que el monkeypatch de las pruebas afecte el
mismo objeto que analyze_eml/analyze_msg leen en tiempo de ejecucion
(settings.ALLOWLIST_DOMAINS/EMAILS).
"""
import json
from io import BytesIO

from contract_schema import assert_matches_success_contract


def test_load_allowlist_missing_file_returns_empty_set(tmp_path):
    import settings

    result = settings.load_allowlist(str(tmp_path / "no_existe.txt"))
    assert result == set()


def test_load_allowlist_ignores_comments_blank_lines_and_normalizes_case(tmp_path):
    import settings

    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text(
        "# comentario\n\nMiDominio.com\n  otro-dominio.com  \n# otro comentario\n",
        encoding="utf-8",
    )

    result = settings.load_allowlist(str(allowlist_file))
    assert result == {"midominio.com", "otro-dominio.com"}


def test_load_allowlist_corrupt_file_returns_empty_set_without_crashing(tmp_path):
    import settings

    corrupt_file = tmp_path / "corrupto.txt"
    corrupt_file.write_bytes(b"\xff\xfe\xfd invalid utf-8 \xff")

    result = settings.load_allowlist(str(corrupt_file))
    assert result == set()


def test_allowlisted_domain_and_email_are_excluded_from_findings(client, api_key, fixtures_dir, monkeypatch):
    import settings

    monkeypatch.setattr(settings, "ALLOWLIST_DOMAINS", {"ejemplo-dominio-malicioso-test.com"})
    monkeypatch.setattr(settings, "ALLOWLIST_EMAILS", {"actor-malicioso-test@ejemplo-remitente-test.com"})

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

    network_indicators = payload["data"]["findings"]["network_indicators"]
    assert "ejemplo-dominio-malicioso-test.com" not in network_indicators["domains"]
    assert "actor-malicioso-test@ejemplo-remitente-test.com" not in network_indicators["email_addresses"]


def test_empty_allowlist_keeps_current_behavior(client, api_key, fixtures_dir, monkeypatch):
    """Regresion: con allowlist vacia (default si los archivos no existen), nada cambia."""
    import settings

    monkeypatch.setattr(settings, "ALLOWLIST_DOMAINS", set())
    monkeypatch.setattr(settings, "ALLOWLIST_EMAILS", set())

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
    domains = payload["data"]["findings"]["network_indicators"]["domains"]
    assert "ejemplo-dominio-malicioso-test.com" in domains
