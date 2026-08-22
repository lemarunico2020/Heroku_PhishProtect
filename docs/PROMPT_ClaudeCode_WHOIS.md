# Encargo para Claude Code — Enriquecimiento WHOIS del dominio remitente (edad de dominio)

## Contexto
Este repo es la API de PhishProtect (Flask, Python). Analiza correos `.eml`/`.msg` y devuelve un
JSON con `analysis_metadata`, `email_metadata`, `cabeceras_email` y `findings`. Hoy la respuesta NO
incluye la fecha de creación del dominio remitente, y un flujo de n8n aguas abajo la necesita para
puntuar la "edad del dominio" (señal fuerte de phishing: los dominios recién registrados suelen ser
maliciosos).

## Objetivo
Agregar a la respuesta un bloque nuevo `info_dominio_remitente` con la fecha de creación del dominio
remitente (y registrar/país/dnssec si están), obtenido por WHOIS. Requisito crítico: debe cubrir
dominios colombianos `.co` y `.com.co` (proveedores externos como APIVOID NO los cubren; por eso se
hace en la API, que sí tiene red completa).

## Entorno de trabajo y pruebas (IMPORTANTE)
- Todo el trabajo es LOCAL, en esta carpeta del proyecto. No tocar el servidor ni EasyPanel.
- El proyecto ya tiene un entorno virtual en `.venv`. USARLO (activarlo) para instalar y probar.
  Si por alguna razón no sirve, crear uno nuevo con `python -m venv .venv` y usarlo.
- Instalar dependencias dentro del venv y correr las pruebas dentro del venv. No instalar nada en el
  Python global del sistema.
- Confirmar en el resumen final qué entorno virtual se usó y que las pruebas corrieron dentro de él.

## Dónde (código)
- Crear un módulo nuevo `whois_lookup.py` con: (a) extracción del dominio registrable, (b) consulta
  WHOIS con caché + timeout + fallo seguro.
- Invocarlo desde `build_analysis_result(...)` en `iocs.py`, derivando el dominio del parámetro
  `email_from`. Así cubre EML y MSG en un solo punto (ambos llaman a `build_analysis_result`).
- Agregar el bloque `info_dominio_remitente` al dict que retorna `build_analysis_result`.

## Forma de salida (bloque nuevo en el resultado del análisis)
```json
"info_dominio_remitente": {
  "dominio_remitente": "<dominio registrable usado en la consulta>",
  "fecha_creacion_dominio": "YYYY-MM-DD",   // o null si no se pudo
  "dominio_registrado_en": "<registrar>",   // o null
  "pais": "<country>",                        // o null
  "dnssec": "<valor>",                        // o null
  "estado_bloqueado": null,
  "whois_ok": true                            // false si hubo fallo/timeout/no encontrado
}
```

## Requisitos técnicos
1. Librería WHOIS basada en sockets, pure-Python. NO depender del binario `whois` del sistema (el
   contenedor Docker puede no tenerlo). Sugerencia: `python-whois` (import `whois`). Si NO devuelve
   fecha para `.co`/`.com.co`, implementar un fallback que consulte por socket el servidor WHOIS del
   registro `.co` (`whois.nic.co` o `whois.registry.co`, puerto 43) y parsear la fecha. Objetivo NO
   negociable: `.co` y `.com.co` deben devolver fecha.
2. `requirements.txt` está APLANADO y se instala con `pip install --no-deps` (leer el comentario del
   archivo). Toda librería nueva se agrega con versión fijada JUNTO A TODAS sus dependencias
   transitivas, o el build de Docker falla. Verificar que el build siga funcionando.
3. Extracción de dominio registrable consciente de sufijos colombianos: para `.co, .com.co, .edu.co,
   .gov.co, .net.co, .org.co, .mil.co, .nom.co` el registrable son las últimas 3 etiquetas
   (`sea.chrysalis.com.co` -> `chrysalis.com.co`); para el resto, las últimas 2
   (`sea.skylandoverseas.com` -> `skylandoverseas.com`). Derivar del `from` (soporta
   `Nombre <user@dom>`). Sin dependencia pesada de Public Suffix List; un mapa interno basta.
4. Timeout corto (p.ej. 5 s) en la consulta WHOIS.
5. Fallo seguro: cualquier error/timeout/no-encontrado => campos en null y `whois_ok=false`, SIN
   lanzar excepción ni romper el análisis. Nunca tumbar una request por un problema de WHOIS.
6. Caché simple por dominio registrable (en memoria, TTL p.ej. 24 h) para no repetir consultas ni
   ser bloqueado por rate-limit del registro.
7. `creation_date` puede venir como `datetime` o lista => tomar la MÁS ANTIGUA y formatear a
   `"YYYY-MM-DD"`.
8. Cambio aislado: no tocar el camino de `find_iocs`/d8s ni el parseo existente.

## Pruebas (dentro del venv)
- Test unitario del extractor de dominio registrable (`.com`, `.co`, `.com.co`, subdominios,
  `Nombre <user@dom>`).
- Test del lookup con la red MOCKEADA (los tests NO salen a la red real).
- Correr `pytest` y asegurar que TODO pasa.
- Prueba manual real (fuera de la suite, con red) con `google.com`, un `.co` real y
  `chrysalis.com.co`: confirmar que los tres devuelven `fecha_creacion_dominio`. Si `.co`/`.com.co`
  no devuelven, implementar el fallback por socket y volver a probar hasta lograrlo. Pegar el
  resultado de esas 3 pruebas en el resumen final.

## Git
- Trabajar en una rama nueva `feature/whois-dominio-remitente` (NO en `main`).
- Commit con mensaje claro en español. Push de la rama al remoto.
- NO desplegar, NO tocar EasyPanel ni variables de entorno, NO commitear secretos ni claves.
- Resumen final: entorno virtual usado, archivos cambiados, dependencias añadidas a
  `requirements.txt`, resultado de las 3 pruebas manuales (`.com`/`.co`/`.com.co`), y pasos para
  poner en producción (mergear la rama + redeploy en EasyPanel para reconstruir la imagen con la
  nueva dependencia).
