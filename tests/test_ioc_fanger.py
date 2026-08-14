"""
HU-02: activar de-fanging de IOCs con ioc-fanger.

Valida que los IOCs defangueados manualmente (hxxp://, dominio[.]com,
actor[at]dominio.com) se detecten igual que sus equivalentes normales,
y que el JSON de respuesta siga cumpliendo el contrato de HU-01.
"""
import json
from io import BytesIO

from contract_schema import assert_matches_success_contract


def test_defanged_iocs_are_recognized_and_match_output_contract(client, api_key, fixtures_dir):
    content = (fixtures_dir / "sample_defanged.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_defanged.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)

    network_indicators = payload["data"]["findings"]["network_indicators"]
    assert "dominio-defangeado-test.com" in network_indicators["domains"]
    assert "https://dominio-defangeado-test.com/pago" in network_indicators["urls"]
    assert "actor-malicioso@dominio-defangeado-test.com" in network_indicators["email_addresses"]
    assert "203.0.113.77" in network_indicators["ipv4"]


def test_non_defanged_iocs_still_work_after_fanger_activation(client, api_key, fixtures_dir):
    """Regresion: el fixture ya usado en HU-01 (IOCs sin defanguear) debe seguir funcionando igual."""
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
