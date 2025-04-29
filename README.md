# PhishProtect API

PhishProtect es una API de análisis de correos electrónicos que extrae indicadores de compromiso (IOCs) de archivos EML y MSG para ayudar en la identificación y análisis rápido de posibles amenazas de phishing.

## Descripción

PhishProtect ofrece un servicio completo para el análisis forense de correos electrónicos sospechosos, permitiendo a los analistas de seguridad identificar rápidamente posibles amenazas. La API procesa archivos EML y MSG y extrae automáticamente diversos indicadores de compromiso, como:

- **Indicadores de red**: Dominios, direcciones IP, URLs y direcciones de correo electrónico
- **Indicadores de archivo**: Hashes (MD5, SHA1, SHA256, SHA512) y rutas de archivos

El servicio está diseñado para integrarse fácilmente en flujos de trabajo de respuesta a incidentes y soluciones SOAR (Security Orchestration, Automation and Response).

## Características

- ✅ **Análisis de archivos EML y MSG**: Procesa correos electrónicos en formato EML y MSG (Microsoft Outlook).
- ✅ **Extracción de IOCs**: Identifica automáticamente indicadores de compromiso.
- ✅ **Procesamiento robusto**: Maneja múltiples codificaciones y formatos de email.
- ✅ **Filtrado inteligente**: Elimina falsos positivos como direcciones de destinatarios.
- ✅ **Resultados estructurados**: Proporciona datos en formato JSON para fácil integración.
- ✅ **API RESTful**: Integración sencilla con otras herramientas y plataformas.
- ✅ **Análisis de adjuntos**: Extrae y calcula hashes de archivos adjuntos.
- ✅ **Detección automática de formato**: Detecta si el archivo es EML o MSG aunque no tenga la extensión correcta.

## Requisitos

- Python 3.9+
- Flask 3.1.0+
- IOC Finder 7.3.0+
- Python-dateutil
- Email-validator
- Extract-msg (para archivos MSG)
- Gunicorn (para producción)

## Instalación y Despliegue

### Opción 1: Despliegue en Heroku (Recomendado)

1. Haz clic en el botón "Deploy to Heroku" arriba
2. Regístrate o inicia sesión en Heroku
3. Configura el nombre de tu aplicación
4. Haz clic en "Deploy app"

### Opción 2: Instalación Local

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/phishprotect.git
cd phishprotect

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la aplicación
python app.py
```

## Uso

### Endpoint API

La API ofrece un endpoint principal para el análisis de archivos EML:

POST /api/v1/analyze_email

Este endpoint detectará automáticamente si el archivo es EML o MSG y lo procesará adecuadamente.

#### Ejemplo de solicitud con cURL:

# Usando el endpoint unificado
curl -X POST -F "email_file=@correo_sospechoso.eml" -H "X-API-Key: tu-api-key" https://tu-app.herokuapp.com/api/v1/analyze_email

#### Ejemplo de respuesta:

{
  "status": "success",
  "timestamp": "2025-03-03T12:34:56.789012",
  "version": "1.1",
  "data": {
    "analysis_metadata": {
      "analysis_id": "IOC-20250303-123456-789",
      "analysis_timestamp": "2025-03-03T12:34:56.789012",
      "file_analyzed": "correo_sospechoso.eml",
      "file_type": "eml"
    },
    "email_metadata": {
      "from": "remitente@dominio-sospechoso.com",
      "to": "destinatario@empresa.com",
      "subject": "Actualización de seguridad urgente",
      "date": "2025-03-02T10:15:30",
      "body_extracted": true,
      "body": "Contenido del correo...",
  },
    "findings": {
      "network_indicators": {
        "domains": ["dominio-malicioso.com", "servidor-c2.net"],
        "ipv4": ["192.168.1.1", "10.0.0.1"],
        "urls": ["https://dominio-malicioso.com/payload.php"],
        "email_addresses": ["actor-malicioso@dominio-sospechoso.com"]
      },
      "file_indicators": {
        "md5_hashes": ["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"],
        "sha256_hashes": ["a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6..."]
      },
      "system_indicators": {
        "registry_keys": ["HKEY_LOCAL_MACHINE\\Software\\Malware"]
      }
    }
  }
}

## Interfaz Web

La aplicación también incluye una interfaz web básica para probar la API directamente desde el navegador:

Accede a tu aplicación en https://tu-app.herokuapp.com/
Selecciona un archivo EML o MSG
Haz clic en "Analizar"
Visualiza los resultados formateados

## Formatos soportados

La API soporta los siguientes formatos de correo electrónico:

- EML: Formato estándar de correo electrónico
- MSG: Formato de Microsoft Outlook

## Seguridad

Este servicio está diseñado para análisis de seguridad. Ten en cuenta:

- No procesa el contenido de archivos adjuntos potencialmente maliciosos.
- No ejecuta código contenido en los correos electrónicos.
- Elimina los archivos temporales después del análisis.
- Implementa logs detallados para auditoría.

## Contribuir

Las contribuciones son bienvenidas. Para contribuir:

1. Haz un fork del repositorio
2. Crea una nueva rama (`git checkout -b feature/nueva-caracteristica`)
3. Realiza tus cambios
4. Ejecuta las pruebas
5. Haz commit de tus cambios (`git commit -am 'Añadir nueva característica'`)
6. Haz push a la rama (`git push origin feature/nueva-caracteristica`)
7. Crea un nuevo Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Para preguntas o soporte, por favor abre un issue en este repositorio.
