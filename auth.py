"""
Autenticacion por API Key (HU-12).

Corrige una vulnerabilidad de timing attack real: la comparacion previa
(`request_api_key != API_KEY`) compara caracter a caracter con salida
temprana, lo que permite inferir la API Key correcta midiendo tiempos de
respuesta. Se reemplaza por hmac.compare_digest, de tiempo constante.
"""
import hmac
from functools import wraps

from flask import request

from settings import API_KEY, logger
from responses import create_json_response, json_response


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si la API Key está configurada
        if not API_KEY:
            logger.error("API Key no configurada en el servidor")
            return json_response(create_json_response(
                status="error",
                error="API Key not configured on server"
            )), 500

        # Verificar si la API Key se proporciona en la solicitud
        request_api_key = request.headers.get('X-API-Key') or request.args.get('api_key')

        if not request_api_key:
            logger.warning("Solicitud sin API Key")
            return json_response(create_json_response(
                status="error",
                error="API Key required"
            )), 401

        # Verificar si la API Key es válida (comparacion de tiempo constante)
        if not hmac.compare_digest(request_api_key, API_KEY):
            logger.warning("API Key inválida proporcionada")
            return json_response(create_json_response(
                status="error",
                error="Invalid API Key"
            )), 403

        return f(*args, **kwargs)
    return decorated_function
