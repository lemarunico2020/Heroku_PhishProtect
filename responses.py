"""
Helpers de formato de respuesta HTTP/JSON, compartidos por auth.py y
routes.py (HU-12).
"""
import json
from datetime import datetime, timezone

from flask import Response


def create_json_response(status="success", data=None, error=None):
    """
    Crea una respuesta JSON estandarizada
    """
    response = {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.1"
    }

    if data is not None:
        response["data"] = data
    if error is not None:
        response["error"] = error

    return response


def json_response(data, status_code=200):
    """
    Crea una respuesta HTTP con JSON formateado (indentado)
    """
    return Response(
        json.dumps(data, indent=2, ensure_ascii=False),
        status=status_code,
        mimetype='application/json'
    )
