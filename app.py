"""
Punto de entrada minimo: crea la app Flask, registra el blueprint de
rutas y arranca el servidor (HU-12: app.py monolitico refactorizado en
modulos, ver README para la estructura completa).

Tambien re-exporta un puñado de simbolos (resolve_log_level, LOG_LEVEL,
MAX_ATTACHMENT_SIZE, structure_iocs, guess_originating_ip,
build_analysis_result, extract_attachment_text) por compatibilidad con
la suite de tests existente, que los referencia como app.<simbolo>. La
allowlist (ALLOWLIST_DOMAINS/ALLOWLIST_EMAILS) y load_allowlist NO se
re-exportan aca: viven y se leen en tiempo de ejecucion directamente
desde settings.py (settings.ALLOWLIST_DOMAINS/EMAILS), para que los
tests puedan seguir haciendo monkeypatch sobre el valor real que usa
analyze_eml/analyze_msg (ver tests/test_allowlist.py).
"""
import os

from flask import Flask

from settings import logger, resolve_log_level, LOG_LEVEL, MAX_ATTACHMENT_SIZE
from routes import bp
from iocs import structure_iocs, guess_originating_ip, build_analysis_result
from parsers.attachments import extract_attachment_text

app = Flask(__name__)
app.register_blueprint(bp)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Iniciando servidor Flask en el puerto {port}")
    app.run(host='0.0.0.0', port=port)
