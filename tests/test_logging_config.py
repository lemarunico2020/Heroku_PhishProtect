"""
HU-04: logging configurable por entorno y sin datos sensibles.

Valida que:
- resolve_log_level() normaliza y cae a INFO ante valores ausentes/invalidos.
- El nivel efectivo por defecto (sin LOG_LEVEL en el entorno) es INFO, no DEBUG.
- Ningun log generado por una solicitud real contiene el valor de la API Key
  ni el cuerpo del correo, y los mensajes exclusivos de DEBUG (cabeceras
  completas) no aparecen cuando el nivel activo es INFO.
"""
import logging
from io import BytesIO
from pathlib import Path

from contract_schema import assert_matches_success_contract


def test_resolve_log_level_defaults_to_info_for_missing_or_invalid_value():
    import app as app_module

    assert app_module.resolve_log_level(None) == "INFO"
    assert app_module.resolve_log_level("") == "INFO"
    assert app_module.resolve_log_level("NO_EXISTE") == "INFO"


def test_resolve_log_level_accepts_known_levels_case_insensitively():
    import app as app_module

    assert app_module.resolve_log_level("debug") == "DEBUG"
    assert app_module.resolve_log_level("Warning") == "WARNING"
    assert app_module.resolve_log_level("ERROR") == "ERROR"


def test_default_log_level_is_info_not_debug():
    import app as app_module

    assert app_module.LOG_LEVEL == "INFO"
    assert logging.getLogger().getEffectiveLevel() == logging.INFO


def _log_file_path():
    for handler in logging.getLogger().handlers:
        if hasattr(handler, "baseFilename"):
            return Path(handler.baseFilename)
    raise RuntimeError("No se encontró un RotatingFileHandler configurado")


def _log_tail_since(offset):
    """
    Lee solo lo agregado al log a partir de `offset`. ioc_finder.log es un
    archivo persistente entre ejecuciones (rota a los 10MB); leer el archivo
    completo mezclaria lineas de sesiones de desarrollo anteriores (algunas
    con LOG_LEVEL=DEBUG) con lo generado por esta prueba puntual.
    """
    path = _log_file_path()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        return f.read()


def test_no_sensitive_data_in_log_at_default_level(client, api_key, fixtures_dir):
    log_offset = _log_file_path().stat().st_size

    content = (fixtures_dir / "sample_phishing.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_phishing.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert_matches_success_contract(response.get_json())

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_tail = _log_tail_since(log_offset)
    assert api_key not in log_tail
    assert "Su cuenta ha sido comprometida" not in log_tail


def test_debug_only_messages_are_suppressed_at_info_level(client, api_key, fixtures_dir):
    """Al nivel INFO (default), el volcado de cabeceras completas (solo DEBUG) no debe aparecer."""
    import app as app_module

    assert app_module.LOG_LEVEL == "INFO"

    log_offset = _log_file_path().stat().st_size

    content = (fixtures_dir / "sample_phishing.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), "sample_phishing.eml")},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_tail = _log_tail_since(log_offset)
    assert "Cabeceras disponibles en EML" not in log_tail
