import os
import sys
from pathlib import Path

import pytest

# La API Key debe fijarse ANTES de importar app.py, porque app.py la lee
# de la variable de entorno una sola vez al cargarse el modulo.
TEST_API_KEY = "test-key-for-pytest-only"
os.environ.setdefault("PHISHPROTECT_API_KEY", TEST_API_KEY)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402
import whois_lookup  # noqa: E402


_SAFE_DEFAULT_WHOIS_RESULT = {
    "fecha_creacion_dominio": None,
    "dominio_registrado_en": None,
    "pais": None,
    "dnssec": None,
    "whois_ok": False,
}


@pytest.fixture(autouse=True)
def no_real_network_whois_lookups(monkeypatch):
    """
    build_analysis_result() (iocs.py) invoca whois_lookup.lookup_domain_info
    para cada correo analizado, incluyendo la mayoria de los tests de esta
    suite (via /api/v1/analyze_email con fixtures reales). Sin este mock,
    TODA la suite dispararia consultas WHOIS reales por red -lenta, fragil
    en CI sin salida a internet, y contra dominios sinteticos que no
    existen-. Los tests especificos de whois_lookup.py sobreescriben este
    mock puntualmente con su propio monkeypatch (que tiene prioridad por
    aplicarse despues, dentro del mismo test).
    """
    monkeypatch.setattr(
        whois_lookup, "lookup_domain_info", lambda domain: dict(_SAFE_DEFAULT_WHOIS_RESULT)
    )


@pytest.fixture(scope="session")
def api_key():
    return os.environ["PHISHPROTECT_API_KEY"]


@pytest.fixture()
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture(scope="session")
def fixtures_dir():
    return Path(__file__).resolve().parent / "fixtures"
