"""
Esquema de contrato del JSON de respuesta de PhishProtect (HU-01).

Este esquema es DELIBERADAMENTE PERMISIVO: solo declara, en cada nivel,
las claves que DEBEN EXISTIR ("required"), sin "additionalProperties": False.

Efecto de ese diseno:
  - El test FALLA si una clave existente se elimina o se renombra.
  - El test NO FALLA si se agrega una clave nueva.

Esto es intencional: las HU siguientes del backlog agregan campos aditivos
(ej. cabeceras_email.originating_ip_guess en HU-05, data.ml_features en
HU-08/09/10) y no deben requerir tocar este esquema para no romperse.
"""

AUTHENTICATION_SCHEMA = {
    "type": "object",
    "required": ["spf", "dkim", "dmarc"],
}

EMAIL_METADATA_SCHEMA = {
    "type": "object",
    "required": [
        "from", "to", "subject", "date", "body_extracted", "body",
        "attachments", "authentication",
    ],
    "properties": {
        "authentication": AUTHENTICATION_SCHEMA,
    },
}

CABECERAS_EMAIL_SCHEMA = {
    "type": "object",
    "required": [
        "return_path", "reply_to", "x_originating_ip", "x_mailer",
        "received_chain", "authentication_results",
    ],
}

NETWORK_INDICATORS_SCHEMA = {
    "type": "object",
    "required": [
        "domains", "ipv4", "ipv6", "urls", "email_addresses",
        "asns", "cidr_ranges",
    ],
}

FILE_INDICATORS_SCHEMA = {
    "type": "object",
    "required": [
        "md5_hashes", "sha1_hashes", "sha256_hashes", "sha512_hashes",
        "file_paths",
    ],
}

SYSTEM_INDICATORS_SCHEMA = {
    "type": "object",
    "required": ["registry_keys", "mac_addresses", "user_agents"],
}

FINDINGS_SCHEMA = {
    "type": "object",
    "required": ["network_indicators", "file_indicators", "system_indicators"],
    "properties": {
        "network_indicators": NETWORK_INDICATORS_SCHEMA,
        "file_indicators": FILE_INDICATORS_SCHEMA,
        "system_indicators": SYSTEM_INDICATORS_SCHEMA,
    },
}

ANALYSIS_METADATA_SCHEMA = {
    "type": "object",
    "required": ["analysis_id", "analysis_timestamp", "file_analyzed", "file_type"],
}

DATA_SCHEMA = {
    "type": "object",
    "required": ["analysis_metadata", "email_metadata", "cabeceras_email", "findings"],
    "properties": {
        "analysis_metadata": ANALYSIS_METADATA_SCHEMA,
        "email_metadata": EMAIL_METADATA_SCHEMA,
        "cabeceras_email": CABECERAS_EMAIL_SCHEMA,
        "findings": FINDINGS_SCHEMA,
    },
}

SUCCESS_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["status", "timestamp", "version", "data"],
    "properties": {
        "status": {"const": "success"},
        "data": DATA_SCHEMA,
    },
}

ERROR_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["status", "timestamp", "version", "error"],
    "properties": {
        "status": {"const": "error"},
    },
}


def assert_matches_success_contract(payload):
    from jsonschema import validate
    validate(instance=payload, schema=SUCCESS_RESPONSE_SCHEMA)


def assert_matches_error_contract(payload):
    from jsonschema import validate
    validate(instance=payload, schema=ERROR_RESPONSE_SCHEMA)
