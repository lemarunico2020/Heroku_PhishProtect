# PhishProtect API - imagen de produccion (HU-13)
#
# Version de Python pineada explicitamente (nunca 'latest') e imagen
# 'slim' para minimizar la superficie de ataque. El contenedor corre
# como usuario no-root para reducir el impacto de una eventual RCE en
# el proceso.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Instalar dependencias primero para aprovechar la cache de capas de
# Docker (solo se reinstalan si cambia requirements.txt).
#
# --no-deps: requirements.txt ya es una lista completa y "aplanada"
# (incluye toda dependencia transitiva realmente usada). Sin --no-deps,
# pip reinstalaria de todos modos sympy/mpmath/hypothesis/d8s-hypothesis
# (~85MB) porque d8s-math/d8s-strings las declaran como dependencias,
# aunque el codigo real de ioc-finder nunca las importa (verificado).
# Ver el comentario al inicio de requirements.txt antes de agregar una
# dependencia nueva: con --no-deps hay que listar explicitamente cada
# paquete que haga falta, incluidas sus propias transitivas.
COPY requirements.txt .
RUN pip install --no-cache-dir --no-deps -r requirements.txt

# Copiar el codigo de la aplicacion. El .dockerignore excluye lo que no
# hace falta en tiempo de ejecucion (tests/, .git/, docs/, logs, etc.)
COPY . .

# Usuario no-root: se crea explicitamente y se le entrega la
# propiedad de /app (necesaria para escribir ioc_finder.log ahi).
RUN groupadd --system phishprotect \
    && useradd --system --gid phishprotect --home-dir /app --shell /usr/sbin/nologin phishprotect \
    && chown -R phishprotect:phishprotect /app
USER phishprotect

# Puerto por defecto (documental; el binding real usa $PORT en runtime)
EXPOSE 5001

# Healthcheck sobre '/' (no requiere API Key, a diferencia de
# /api/v1/check_auth, que NUNCA debe exponerse como healthcheck
# publico porque exige la API Key real). Se usa urllib de la stdlib en
# vez de instalar curl/wget, para no agrandar la imagen.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '5001') + '/', timeout=3)" || exit 1

# Variables de entorno (PHISHPROTECT_API_KEY, MAX_FILE_SIZE_MB, LOG_LEVEL,
# WEB_CONCURRENCY, GUNICORN_THREADS, GUNICORN_TIMEOUT, etc.) se inyectan
# en runtime (docker run -e / EasyPanel / docker-compose), nunca aca.
CMD gunicorn -w ${WEB_CONCURRENCY:-2} --threads ${GUNICORN_THREADS:-2} -k gthread --timeout ${GUNICORN_TIMEOUT:-60} -b 0.0.0.0:${PORT:-5001} app:app
