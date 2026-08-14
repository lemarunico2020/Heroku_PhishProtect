"""
Endpoints Flask de PhishProtect (HU-12: extraido de app.py a un
Blueprint, registrado por app.py).
"""
import os
import tempfile

from flask import Blueprint, request
from email import policy
from email.parser import BytesParser
import extract_msg  # Importación para archivos MSG

from settings import MAX_FILE_SIZE, logger
from auth import require_api_key
from responses import create_json_response, json_response
from parsers.eml import analyze_eml
from parsers.msg import analyze_msg

bp = Blueprint('phishprotect', __name__)


def check_file_size(file, max_size_bytes=MAX_FILE_SIZE):
    """
    Verifica si el tamaño del archivo excede el límite máximo
    """
    file.seek(0, os.SEEK_END)
    file_size = file.tell()  # Tamaño en bytes
    file.seek(0)  # Volver al inicio del archivo
    if file_size > max_size_bytes:
        logger.warning(f"Archivo rechazado: {file_size/1024/1024:.2f} MB (límite: {max_size_bytes/1024/1024:.1f} MB)")
        return False, file_size, f"El archivo excede el tamaño máximo permitido de {max_size_bytes/1024/1024:.1f} MB (tamaño actual: {file_size/1024/1024:.2f} MB). Contacte al administrador si necesita procesar archivos más grandes."

    return True, file_size, ""


@bp.route('/api/v1/analyze_email', methods=['POST'])
@require_api_key
def analyze_email_file():
    """
    Endpoint unificado para analizar archivos de correo electrónico (EML y MSG)
    Versión mejorada con mayor flexibilidad y optimizaciones
    """
    logger.info("Recibida solicitud de análisis de correo electrónico")
    try:
        # Buscar el archivo en cualquiera de los posibles campos del formulario
        file = None
        file_field_name = None

        # Posibles nombres de campo para archivos
        field_names = ['email_file', 'eml_file', 'msg_file', 'file']

        for field in field_names:
            if field in request.files and request.files[field].filename != '':
                file = request.files[field]
                file_field_name = field
                break

        # Si no se encuentra ningún archivo
        if not file:
            # Verificar si hay algún archivo, aunque esté en otro campo
            all_files = list(request.files.values())
            if all_files and len(all_files) > 0 and all_files[0].filename != '':
                file = all_files[0]
                file_field_name = list(request.files.keys())[0]
                logger.debug(f"Encontrado archivo en campo alternativo: {file_field_name}")
            else:
                logger.warning("No se ha subido ningún archivo")
                return json_response(create_json_response(
                    status="error",
                    error="No file uploaded"
                )), 400

        logger.debug(f"Nombre del archivo recibido: {file.filename} en campo: {file_field_name}")

        if file.filename == '':
            logger.warning("No se ha seleccionado ningún archivo")
            return json_response(create_json_response(
                status="error",
                error="No file selected"
            )), 400

        # Verificar el tamaño del archivo
        size_ok, file_size, error_message = check_file_size(file, MAX_FILE_SIZE)
        if not size_ok:
            logger.warning(f"El archivo excede el tamaño máximo: {file_size} bytes")
            return json_response(create_json_response(
                status="error",
                error=error_message
            )), 413

        # Determinar el tipo de archivo basado en la extensión y contenido
        file_extension = file.filename.lower().split('.')[-1] if '.' in file.filename else ''

        # Guardar el archivo temporalmente para poder analizarlo
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as temp_file:
            logger.debug(f"Guardando archivo temporal en: {temp_file.name}")

            # Guardamos el archivo para poder examinarlo
            file.save(temp_file.name)

            temp_filename = temp_file.name

            # Intentamos determinar el tipo de archivo
            file_type_detected = None

            # Si la extensión es clara, la usamos
            if file_extension in ['eml', 'msg']:
                file_type_detected = file_extension
                logger.debug(f"Tipo de archivo determinado por extensión: {file_type_detected}")

            # Si no, intentamos determinar por el nombre del campo
            elif 'eml' in file_field_name.lower():
                file_type_detected = 'eml'
                logger.debug(f"Tipo de archivo determinado por nombre de campo: {file_type_detected}")

            elif 'msg' in file_field_name.lower():
                file_type_detected = 'msg'
                logger.debug(f"Tipo de archivo determinado por nombre de campo: {file_type_detected}")

            # Si aún no podemos determinar, intentamos examinar el contenido del archivo
            else:
                try:
                    # Intentar abrir como EML
                    with open(temp_filename, 'rb') as f:
                        try:
                            BytesParser(policy=policy.default).parse(f)
                            file_type_detected = 'eml'
                            logger.debug("Archivo detectado como EML por su contenido")

                        except Exception as e:
                            logger.debug(f"No es un archivo EML válido: {str(e)}")

                            # Intentar abrir como MSG
                            try:
                                test_msg = extract_msg.openMsg(temp_filename)
                                test_msg.close()  # Cerrar inmediatamente después de verificar
                                file_type_detected = 'msg'
                                logger.debug("Archivo detectado como MSG por su contenido")

                            except Exception as e:
                                logger.debug(f"No es un archivo MSG válido: {str(e)}")

                except Exception as e:
                    logger.error(f"Error al intentar determinar el tipo de archivo: {str(e)}")

            # Si no pudimos determinar el tipo, devolver error
            if not file_type_detected:
                # Eliminar el archivo temporal
                if os.path.exists(temp_filename):
                    os.remove(temp_filename)

                logger.warning("No se pudo determinar el tipo de archivo")

                return json_response(create_json_response(
                    status="error",
                    error="File must be an EML or MSG file. Could not determine file type."

                )), 400

            # Asignar el tipo detectado
            file_extension = file_type_detected

        # El archivo ya fue guardado anteriormente para la detección del tipo
        logger.debug(f"Usando archivo temporal ya guardado: {temp_filename}")

        try:
            logger.debug(f"Iniciando análisis del archivo temporal: {temp_filename} como {file_extension}")

            # Analizar según el tipo de archivo
            if file_extension == 'eml':
                results = analyze_eml(temp_filename)
            else:  # msg
                results = analyze_msg(temp_filename)

            logger.info("Análisis exitoso, preparando respuesta")
            response = create_json_response(
                status="success",
                data=results
            )
            return json_response(response, 200)

        except ValueError as ve:
            # Manejar específicamente errores de valor (como tamaño excesivo)
            logger.warning(f"Error de validación: {str(ve)}")
            return json_response(create_json_response(
                status="error",
                error=str(ve)
            )), 413

        except Exception as e:
            logger.error(f"Error al analizar el archivo: {str(e)}", exc_info=True)
            return json_response(create_json_response(
                status="error",
                error=str(e)
            )), 500

        finally:
            if os.path.exists(temp_filename):
                logger.debug(f"Eliminando archivo temporal: {temp_filename}")
                os.remove(temp_filename)

    except Exception as e:
        logger.error(f"Error al procesar el archivo: {str(e)}", exc_info=True)
        return json_response(create_json_response(
            status="error",
            error=str(e)
        )), 500


def process_email_file(expected_extension, field_name, analysis_function):
    """
    Función auxiliar para procesar archivos de email (EML o MSG)
    """
    file = request.files.get(field_name)
    if not file:
        # Buscar en campos alternativos
        for field in request.files:
            if request.files[field].filename.lower().endswith(f'.{expected_extension}'):
                file = request.files[field]
                break

    if not file or file.filename == '':
        return json_response(create_json_response(
            status="error",
            error=f"No {expected_extension.upper()} file uploaded"
        )), 400

    # Verificar tamaño
    size_ok, file_size, error_message = check_file_size(file, MAX_FILE_SIZE)
    if not size_ok:
        return json_response(create_json_response(status="error", error=error_message)), 413

    # Guardar y analizar
    with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{expected_extension}') as temp_file:
        file.save(temp_file.name)
        temp_filename = temp_file.name

    try:
        results = analysis_function(temp_filename)
        return json_response(create_json_response(status="success", data=results), 200)
    except ValueError as ve:
        return json_response(create_json_response(status="error", error=str(ve)), 413)
    except Exception as e:
        logger.error(f"Error analyzing {expected_extension.upper()}: {str(e)}", exc_info=True)
        return json_response(create_json_response(status="error", error=str(e)), 500)
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)


# Mantener los endpoints originales por compatibilidad
@bp.route('/api/v1/analyze_eml', methods=['POST'])
@require_api_key
def analyze_eml_file():
    """
    Endpoint para analizar archivos EML (legacy, usa process_email_file)
    """
    logger.info("Recibida solicitud de análisis de EML")
    return process_email_file('eml', 'eml_file', analyze_eml)


@bp.route('/api/v1/analyze_msg', methods=['POST'])
@require_api_key
def analyze_msg_file():
    """
    Endpoint para analizar archivos MSG (legacy, usa process_email_file)
    """
    logger.info("Recibida solicitud de análisis de MSG")
    return process_email_file('msg', 'msg_file', analyze_msg)


# Ruta para la página principal
@bp.route('/', methods=['GET'])
def home():
    """
    Página principal que muestra información sobre la API
    """
    return """
    <html>
    <head>
        <title>PhishProtect API</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            h1 { color: #2c3e50; }
            .container { max-width: 800px; margin: 0 auto; }
            .endpoint { background-color: #f8f9fa; border-left: 4px solid #4CAF50; padding: 10px; margin-bottom: 20px; }
            code { background-color: #f1f1f1; padding: 2px 5px; border-radius: 3px; }
            .note { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PhishProtect API</h1>
            <p>Esta es la API de análisis de correos electrónicos PhishProtect. Para utilizar esta API, necesitas una API Key válida.</p>

            <div class="note">
                <strong>Nota:</strong> El tamaño máximo de archivo permitido es de 15MB. Los archivos más grandes serán rechazados.
            </div>

            <h2>Endpoints disponibles:</h2>

            <div class="endpoint">
                <h3>Analizar archivo de correo (Unificado)</h3>
                <p><code>POST /api/v1/analyze_email</code></p>
                <p>Este endpoint permite analizar archivos EML o MSG para extraer Indicadores de Compromiso (IOCs) y resultados de autenticación (SPF, DKIM, DMARC).</p>
                <p>Requiere autenticación mediante API Key.</p>
            </div>

            <div class="endpoint">
                <h3>Analizar archivo EML</h3>
                <p><code>POST /api/v1/analyze_eml</code></p>
                <p>Este endpoint permite analizar un archivo EML para extraer Indicadores de Compromiso (IOCs) y resultados de autenticación (SPF, DKIM, DMARC).</p>
                <p>Requiere autenticación mediante API Key.</p>
            </div>

            <div class="endpoint">
                <h3>Analizar archivo MSG</h3>
                <p><code>POST /api/v1/analyze_msg</code></p>
                <p>Este endpoint permite analizar un archivo MSG para extraer Indicadores de Compromiso (IOCs) y resultados de autenticación (SPF, DKIM, DMARC).</p>
                <p>Requiere autenticación mediante API Key.</p>
            </div>

            <div class="endpoint">
                <h3>Verificar autenticación</h3>
                <p><code>GET /api/v1/check_auth</code></p>
                <p>Este endpoint permite verificar si tu API Key es válida.</p>
            </div>

            <h2>Autenticación</h2>
            <p>Todas las solicitudes deben incluir una API Key válida de alguna de estas formas:</p>
            <ul>
                <li>Como encabezado HTTP: <code>X-API-Key: tu-api-key</code></li>
                <li>Como parámetro de URL: <code>?api_key=tu-api-key</code></li>
            </ul>

            <h2>Formatos soportados</h2>
            <p>La API soporta los siguientes formatos de correo electrónico:</p>
            <ul>
                <li><strong>EML</strong>: Formato estándar de correo electrónico</li>
                <li><strong>MSG</strong>: Formato de Microsoft Outlook</li>
            </ul>

            <h2>Límites y recomendaciones</h2>
            <ul>
                <li>Tamaño máximo de archivo: 15MB</li>
                <li>Se recomienda un tiempo de espera (timeout) de al menos 60 segundos al hacer solicitudes a esta API</li>
                <li>Para archivos grandes, el análisis puede llevar más tiempo</li>
            </ul>
        </div>
    </body>
    </html>
    """


# Nueva ruta para verificar la autenticación
@bp.route('/api/v1/check_auth', methods=['GET'])
@require_api_key
def check_auth():
    """
    Endpoint para verificar la autenticación de la API Key
    """
    return json_response(create_json_response(
        status="success",
        data={"message": "API Key válida"}
    )), 200
