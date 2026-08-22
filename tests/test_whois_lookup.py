"""
Enriquecimiento WHOIS del dominio remitente (encargo ad-hoc, agosto 2026).
Ver docs/PROMPT_ClaudeCode_WHOIS.md para el encargo completo.

Todos los tests de esta suite van con la red MOCKEADA (nunca salen a la
red real) - ver conftest.py, fixture autouse no_real_network_whois_lookups,
que ademas protege al resto de la suite (build_analysis_result se llama
desde casi todos los tests via /api/v1/analyze_email). Las pruebas
manuales reales (.com/.co/.com.co, con red de verdad) se documentan por
separado en el resumen de la tarea, fuera de pytest.
"""
from datetime import datetime

import pytest

import whois_lookup

# Referencia a la funcion real, capturada en tiempo de coleccion (antes de
# que corra ningun fixture/monkeypatch). El fixture autouse de conftest.py
# reemplaza whois_lookup.lookup_domain_info por una version segura de red
# para el resto de la suite; el fixture autouse de mas abajo la restaura
# para los tests de este archivo, que ejercitan la logica real (cache,
# fallback .co, reintentos) mientras mantienen mockeadas solo las piezas
# de bajo nivel que tocarian la red (_python_whois, _raw_whois_query).
_REAL_LOOKUP_DOMAIN_INFO = whois_lookup.lookup_domain_info


@pytest.fixture(autouse=True)
def _use_real_lookup_domain_info_with_clean_cache(monkeypatch):
    monkeypatch.setattr(whois_lookup, "lookup_domain_info", _REAL_LOOKUP_DOMAIN_INFO)
    monkeypatch.setattr(whois_lookup, "_cache", {})


class _FakeWhoisResult:
    """Imita el objeto que devuelve whois.whois(): acceso por atributo."""

    def __init__(self, creation_date=None, registrar=None, country=None, dnssec=None):
        self.creation_date = creation_date
        self.registrar = registrar
        self.country = country
        self.dnssec = dnssec


def _fake_python_whois_module(whois_func):
    return type("FakePythonWhois", (), {"whois": staticmethod(whois_func)})


# ---------------------------------------------------------------------------
# extract_registrable_domain
# ---------------------------------------------------------------------------

def test_extract_domain_plain_com():
    assert whois_lookup.extract_registrable_domain("user@ejemplo-test.com") == "ejemplo-test.com"


def test_extract_domain_subdomain_com():
    assert whois_lookup.extract_registrable_domain("user@mail.ejemplo-test.com") == "ejemplo-test.com"


def test_extract_domain_plain_co():
    assert whois_lookup.extract_registrable_domain("user@ejemplo-test.co") == "ejemplo-test.co"


def test_extract_domain_com_co_with_subdomain():
    assert whois_lookup.extract_registrable_domain("user@sea.chrysalis-test.com.co") == "chrysalis-test.com.co"


def test_extract_domain_com_co_without_subdomain():
    assert whois_lookup.extract_registrable_domain("user@chrysalis-test.com.co") == "chrysalis-test.com.co"


def test_extract_domain_other_colombian_second_level_suffixes():
    assert whois_lookup.extract_registrable_domain("user@sub.universidad-test.edu.co") == "universidad-test.edu.co"
    assert whois_lookup.extract_registrable_domain("user@entidad-test.gov.co") == "entidad-test.gov.co"
    assert whois_lookup.extract_registrable_domain("user@empresa-test.net.co") == "empresa-test.net.co"


def test_extract_domain_name_and_angle_brackets_format():
    result = whois_lookup.extract_registrable_domain('"Soporte Seguridad" <soporte@ejemplo-remitente-test.com>')
    assert result == "ejemplo-remitente-test.com"


def test_extract_domain_non_colombian_domain_similar_looking():
    """
    Regresion del ejemplo del encargo: un dominio .com "comun" no debe
    confundirse con la familia .co solo por contener esas letras.
    """
    assert whois_lookup.extract_registrable_domain("user@sea.skylandoverseas-test.com") == "skylandoverseas-test.com"


def test_extract_domain_bare_domain_without_at():
    assert whois_lookup.extract_registrable_domain("mail.ejemplo-test.com") == "ejemplo-test.com"


def test_extract_domain_none_input_returns_none():
    assert whois_lookup.extract_registrable_domain(None) is None


def test_extract_domain_empty_string_returns_none():
    assert whois_lookup.extract_registrable_domain("") is None


def test_extract_domain_no_domain_present_returns_none():
    assert whois_lookup.extract_registrable_domain("no hay dominio aqui") is None


# ---------------------------------------------------------------------------
# _earliest_date
# ---------------------------------------------------------------------------

def test_earliest_date_single_datetime():
    assert whois_lookup._earliest_date(datetime(2020, 3, 15)) == "2020-03-15"


def test_earliest_date_list_takes_earliest():
    dates = [datetime(2021, 1, 1), datetime(2019, 6, 15), datetime(2022, 1, 1)]
    assert whois_lookup._earliest_date(dates) == "2019-06-15"


def test_earliest_date_none_returns_none():
    assert whois_lookup._earliest_date(None) is None


def test_earliest_date_empty_list_returns_none():
    assert whois_lookup._earliest_date([]) is None


def test_earliest_date_parses_iso_like_string():
    assert whois_lookup._earliest_date("2022-08-16T16:15:50.0Z") == "2022-08-16"


# ---------------------------------------------------------------------------
# lookup_domain_info (red mockeada)
# ---------------------------------------------------------------------------

def test_lookup_domain_info_uses_python_whois_when_available(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})

    def fake_whois(domain, timeout=5):
        assert domain == "ejemplo-mock-test.com"
        return _FakeWhoisResult(
            creation_date=datetime(2020, 5, 1),
            registrar="Registrar Falso Inc.",
            country="US",
            dnssec="unsigned",
        )

    monkeypatch.setattr(whois_lookup, "_python_whois", _fake_python_whois_module(fake_whois))

    result = whois_lookup.lookup_domain_info("ejemplo-mock-test.com")
    assert result == {
        "fecha_creacion_dominio": "2020-05-01",
        "dominio_registrado_en": "Registrar Falso Inc.",
        "pais": "US",
        "dnssec": "unsigned",
        "whois_ok": True,
    }


def test_lookup_domain_info_python_whois_failure_returns_safe_default(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})

    def fake_whois(domain, timeout=5):
        raise Exception("timeout simulado")

    monkeypatch.setattr(whois_lookup, "_python_whois", _fake_python_whois_module(fake_whois))

    result = whois_lookup.lookup_domain_info("ejemplo-falla-test.com")
    assert result == {
        "fecha_creacion_dominio": None,
        "dominio_registrado_en": None,
        "pais": None,
        "dnssec": None,
        "whois_ok": False,
    }


def test_lookup_domain_info_co_fallback_when_python_whois_has_no_date(monkeypatch):
    """Objetivo no negociable del encargo: .co debe devolver fecha, via el fallback crudo si hace falta."""
    monkeypatch.setattr(whois_lookup, "_cache", {})
    monkeypatch.setattr(
        whois_lookup, "_python_whois", _fake_python_whois_module(lambda d, timeout=5: _FakeWhoisResult())
    )

    def fake_raw_query(server, domain, timeout=5, attempts=2):
        assert server == whois_lookup._CO_REGISTRY_WHOIS_SERVER
        assert domain == "ejemplo-co-test.co"
        return (
            "Domain Name: EJEMPLO-CO-TEST.CO\n"
            "Creation Date: 2022-08-16T16:15:50.0Z\n"
            "Registrar: Falso Registrar SAS\n"
            "DNSSEC: unsigned\n"
        )

    monkeypatch.setattr(whois_lookup, "_raw_whois_query", fake_raw_query)

    result = whois_lookup.lookup_domain_info("ejemplo-co-test.co")
    assert result["fecha_creacion_dominio"] == "2022-08-16"
    assert result["dominio_registrado_en"] == "Falso Registrar SAS"
    assert result["dnssec"] == "unsigned"
    assert result["whois_ok"] is True


def test_lookup_domain_info_com_co_fallback_when_python_whois_has_no_date(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})
    monkeypatch.setattr(
        whois_lookup, "_python_whois", _fake_python_whois_module(lambda d, timeout=5: _FakeWhoisResult())
    )

    def fake_raw_query(server, domain, timeout=5, attempts=2):
        assert domain == "chrysalis-test.com.co"
        return "Creation Date: 2022-08-16T16:15:50.0Z\nRegistrar: Falso Registrar SAS\n"

    monkeypatch.setattr(whois_lookup, "_raw_whois_query", fake_raw_query)

    result = whois_lookup.lookup_domain_info("chrysalis-test.com.co")
    assert result["fecha_creacion_dominio"] == "2022-08-16"
    assert result["whois_ok"] is True


def test_lookup_domain_info_co_fallback_also_fails_returns_safe_default(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})
    monkeypatch.setattr(
        whois_lookup, "_python_whois", _fake_python_whois_module(lambda d, timeout=5: _FakeWhoisResult())
    )
    monkeypatch.setattr(whois_lookup, "_raw_whois_query", lambda *a, **k: None)

    result = whois_lookup.lookup_domain_info("ejemplo-co-sinfecha-test.co")
    assert result["whois_ok"] is False
    assert result["fecha_creacion_dominio"] is None


def test_lookup_domain_info_non_co_domain_never_uses_raw_fallback(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})
    monkeypatch.setattr(
        whois_lookup, "_python_whois", _fake_python_whois_module(lambda d, timeout=5: _FakeWhoisResult())
    )
    calls = []
    monkeypatch.setattr(whois_lookup, "_raw_whois_query", lambda *a, **k: calls.append(a) or None)

    result = whois_lookup.lookup_domain_info("ejemplo-sinfecha-test.com")
    assert calls == []
    assert result["whois_ok"] is False


def test_lookup_domain_info_none_domain_returns_safe_default_without_network(monkeypatch):
    calls = []
    monkeypatch.setattr(
        whois_lookup,
        "_python_whois",
        _fake_python_whois_module(lambda *a, **k: calls.append(a) or _FakeWhoisResult()),
    )

    result = whois_lookup.lookup_domain_info(None)
    assert calls == []
    assert result["whois_ok"] is False


def test_lookup_domain_info_uses_cache_on_second_call(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})
    call_count = {"n": 0}

    def fake_whois(domain, timeout=5):
        call_count["n"] += 1
        return _FakeWhoisResult(creation_date=datetime(2020, 1, 1))

    monkeypatch.setattr(whois_lookup, "_python_whois", _fake_python_whois_module(fake_whois))

    first = whois_lookup.lookup_domain_info("ejemplo-cache-test.com")
    second = whois_lookup.lookup_domain_info("ejemplo-cache-test.com")
    assert first == second
    assert call_count["n"] == 1


def test_lookup_domain_info_cache_expired_triggers_new_query(monkeypatch):
    call_count = {"n": 0}

    def fake_whois(domain, timeout=5):
        call_count["n"] += 1
        return _FakeWhoisResult(creation_date=datetime(2020, 1, 1))

    monkeypatch.setattr(whois_lookup, "_python_whois", _fake_python_whois_module(fake_whois))
    monkeypatch.setattr(
        whois_lookup,
        "_cache",
        {
            "ejemplo-ttl-test.com": (
                0,  # timestamp muy en el pasado -> vencido
                {
                    "fecha_creacion_dominio": "2000-01-01",
                    "dominio_registrado_en": None,
                    "pais": None,
                    "dnssec": None,
                    "whois_ok": True,
                },
            )
        },
    )

    result = whois_lookup.lookup_domain_info("ejemplo-ttl-test.com")
    assert call_count["n"] == 1
    assert result["fecha_creacion_dominio"] == "2020-01-01"


def test_lookup_domain_info_when_python_whois_unavailable(monkeypatch):
    monkeypatch.setattr(whois_lookup, "_cache", {})
    monkeypatch.setattr(whois_lookup, "_python_whois", None)

    result = whois_lookup.lookup_domain_info("ejemplo-sin-lib-test.com")
    assert result["whois_ok"] is False


def test_lookup_domain_info_python_whois_retries_on_transient_failure(monkeypatch):
    """Se observaron fallos intermitentes reales incluso contra .com; el modulo debe reintentar."""
    monkeypatch.setattr(whois_lookup, "_cache", {})
    attempts = {"n": 0}

    def flaky_whois(domain, timeout=5):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise Exception("fallo transitorio simulado")
        return _FakeWhoisResult(creation_date=datetime(2020, 1, 1))

    monkeypatch.setattr(whois_lookup, "_python_whois", _fake_python_whois_module(flaky_whois))

    result = whois_lookup.lookup_domain_info("ejemplo-flaky-test.com")
    assert attempts["n"] == 2
    assert result["whois_ok"] is True
