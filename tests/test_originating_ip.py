"""
HU-05: extraer la IP del primer salto (mas cercano al origen) en la
cadena Received.

Valida guess_originating_ip() de forma aislada (incluyendo exclusion de
rangos privados/reservados/loopback/multicast, tanto IPv4 como IPv6) y el
campo aditivo data.cabeceras_email.originating_ip_guess end-to-end, sin
romper el contrato de salida de HU-01.
"""
import json
from io import BytesIO

from contract_schema import assert_matches_success_contract


def test_empty_received_chain_returns_none():
    import app as app_module

    assert app_module.guess_originating_ip([]) is None


def test_only_private_ips_returns_none():
    import app as app_module

    chain = [
        "from a (a [10.0.0.5]) by b; Wed, 12 Aug 2026 10:16:00 +0000",
        "from c (c [192.168.1.1]) by d; Wed, 12 Aug 2026 10:15:50 +0000",
    ]
    assert app_module.guess_originating_ip(chain) is None


def test_documentation_ranges_rfc5737_are_treated_as_non_public():
    """Los rangos TEST-NET (RFC5737) usados en los fixtures sinteticos no deben reportarse como IP publica."""
    import app as app_module

    chain = ["from mx (mx [203.0.113.10]) by y; Wed, 12 Aug 2026 10:15:25 +0000"]
    assert app_module.guess_originating_ip(chain) is None


def test_returns_first_public_ip_walking_from_oldest_hop_to_newest():
    import app as app_module

    # orden tal cual devuelve msg.get_all('received'): mas reciente primero
    chain = [
        "from internal (internal [10.0.0.5]) by mx; Wed, 12 Aug 2026 10:16:00 +0000",
        "from relay (relay [8.8.8.8]) by internal; Wed, 12 Aug 2026 10:15:50 +0000",
        "from origin (origin [203.0.113.10]) by relay; Wed, 12 Aug 2026 10:15:25 +0000",
    ]
    assert app_module.guess_originating_ip(chain) == "8.8.8.8"


def test_ignores_malformed_non_ip_text_without_crashing():
    import app as app_module

    chain = ["from unknown (unknown [not-an-ip]) by mx; Wed, 12 Aug 2026 10:16:00 +0000"]
    assert app_module.guess_originating_ip(chain) is None


def test_excludes_multicast_addresses():
    import app as app_module

    chain = [
        "from mcast (mcast [224.0.0.1]) by mx; Wed, 12 Aug 2026 10:16:00 +0000",
        "from mcast6 (mcast6 [ff02::1]) by mx; Wed, 12 Aug 2026 10:15:50 +0000",
    ]
    assert app_module.guess_originating_ip(chain) is None


def test_recognizes_public_ipv6_address():
    import app as app_module

    chain = ["from relay (relay [2001:4860:4860::8888]) by mx; Wed, 12 Aug 2026 10:16:00 +0000"]
    assert app_module.guess_originating_ip(chain) == "2001:4860:4860::8888"


def test_originating_ip_guess_field_present_and_matches_output_contract(client, api_key, fixtures_dir):
    content = (fixtures_dir / "sample_received_chain.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_received_chain.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)

    cabeceras = payload["data"]["cabeceras_email"]
    assert cabeceras["originating_ip_guess"] == "8.8.8.8"


def test_originating_ip_guess_is_null_when_only_test_net_ips_present(client, api_key, fixtures_dir):
    """Regresion: el fixture de HU-01/02 (un unico Received con IP RFC5737) sigue funcionando, sin IP publica detectada."""
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
    assert payload["data"]["cabeceras_email"]["originating_ip_guess"] is None
