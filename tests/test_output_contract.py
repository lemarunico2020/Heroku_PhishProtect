"""
HU-01: test de regresion del contrato de salida (golden JSON).

Objetivo: garantizar que la estructura del JSON de respuesta de
/api/v1/analyze_email no cambie de forma incompatible, ya que los flujos
de n8n dependen de estas rutas exactas. Ver tests/contract_schema.py para
el diseno del esquema (permisivo a nuevas claves, estricto con las
existentes).

Nota sobre MSG: no se incluye un fixture .msg binario real porque
generar uno de forma programatica requiere Outlook/pywin32 (no disponible
en un entorno headless). analyze_eml y analyze_msg convergen en la misma
funcion build_analysis_result/structure_iocs, asi que el contrato para
MSG se valida directamente sobre esas funciones compartidas en
test_build_analysis_result_matches_output_contract_for_msg_like_data.
"""
import json
from io import BytesIO

import app as app_module
from contract_schema import assert_matches_error_contract, assert_matches_success_contract


def _load_fixture(fixtures_dir, name):
    return (fixtures_dir / name).read_bytes()


def _post_email(client, filename, content, api_key=None):
    headers = {"X-API-Key": api_key} if api_key else {}
    return client.post(
        "/api/v1/analyze_email",
        data={"email_file": (BytesIO(content), filename)},
        headers=headers,
        content_type="multipart/form-data",
    )


def test_analyze_email_multipart_eml_matches_output_contract(client, api_key, fixtures_dir):
    content = _load_fixture(fixtures_dir, "sample_phishing.eml")
    response = _post_email(client, "sample_phishing.eml", content, api_key)

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)

    data = payload["data"]
    assert data["analysis_metadata"]["file_type"] == "eml"
    assert "ejemplo-dominio-malicioso-test.com" in data["findings"]["network_indicators"]["domains"]
    assert len(data["email_metadata"]["attachments"]) == 1
    assert data["email_metadata"]["authentication"]["spf"] == "FAIL"


def test_analyze_email_simple_eml_matches_output_contract(client, api_key, fixtures_dir):
    content = _load_fixture(fixtures_dir, "sample_simple.eml")
    response = _post_email(client, "sample_simple.eml", content, api_key)

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)

    data = payload["data"]
    assert data["email_metadata"]["attachments"] == []
    assert data["email_metadata"]["authentication"]["spf"] == "NOT_FOUND"


def test_missing_api_key_matches_error_contract(client, fixtures_dir):
    content = _load_fixture(fixtures_dir, "sample_simple.eml")
    response = _post_email(client, "sample_simple.eml", content, api_key=None)

    assert response.status_code == 401
    assert_matches_error_contract(json.loads(response.data))


def test_invalid_api_key_matches_error_contract(client, fixtures_dir):
    content = _load_fixture(fixtures_dir, "sample_simple.eml")
    response = _post_email(client, "sample_simple.eml", content, api_key="clave-incorrecta")

    assert response.status_code == 403
    assert_matches_error_contract(json.loads(response.data))


def test_no_file_uploaded_matches_error_contract(client, api_key):
    response = client.post(
        "/api/v1/analyze_email",
        data={},
        headers={"X-API-Key": api_key},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert_matches_error_contract(json.loads(response.data))


def test_unparseable_content_falls_back_to_eml_and_matches_output_contract(client, api_key):
    """
    Comportamiento actual (no un requisito, solo lo que hace hoy el codigo):
    email.parser.BytesParser es muy permisivo y no falla al parsear texto
    arbitrario, asi que un archivo que no es EML/MSG termina clasificado
    como EML "vacio" (sin cabeceras) en vez de rechazarse con 400. Se deja
    registrado como test de regresion de la conducta actual; si se decide
    endurecer la deteccion de tipo de archivo, seria una HU nueva y este
    test se actualizaria a la par.
    """
    response = _post_email(
        client, "archivo.xyz", b"contenido que no es ni eml ni msg valido", api_key
    )

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert_matches_success_contract(payload)
    assert payload["data"]["analysis_metadata"]["file_type"] == "eml"


def test_build_analysis_result_matches_output_contract_for_msg_like_data():
    structured_iocs = app_module.structure_iocs(
        iocs={
            "domains": {"ejemplo-msg-test.com"},
            "ipv4s": {"203.0.113.20"},
        },
        filtered_emails=set(),
        filtered_domains={"ejemplo-msg-test.com"},
    )
    result = app_module.build_analysis_result(
        file_path="C:/temp/sample.msg",
        file_type="msg",
        email_from="remitente-msg-test@ejemplo-msg-test.com",
        email_to="destinatario@empresa-cliente-test.com",
        subject="Correo de prueba MSG",
        email_date="2026-08-12T09:00:00+00:00",
        email_body="Cuerpo de prueba MSG",
        attachments=[],
        auth_results={"spf": "PASS", "dkim": "FAIL", "dmarc": "NOT_FOUND"},
        email_headers={
            "return_path": None,
            "reply_to": None,
            "x_originating_ip": None,
            "x_mailer": None,
            "received_chain": [],
            "authentication_results": None,
        },
        structured_iocs=structured_iocs,
    )

    assert_matches_success_contract(
        {"status": "success", "timestamp": "2026-08-12T09:00:00+00:00", "version": "1.1", "data": result}
    )
    assert result["analysis_metadata"]["file_type"] == "msg"
