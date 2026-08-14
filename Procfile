web: gunicorn -w ${WEB_CONCURRENCY:-2} --threads ${GUNICORN_THREADS:-2} -k gthread --timeout ${GUNICORN_TIMEOUT:-60} app:app
