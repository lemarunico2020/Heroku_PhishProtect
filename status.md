# Estado de ejecución — PhishProtect

> **Este archivo es la fuente única de verdad del avance.** Al iniciar una sesión nueva, basta con leer este archivo para saber qué se hizo y qué sigue. El backlog completo con criterios de aceptación, tareas técnicas y seguridad de cada HU vive en [docs/sprints-historias-usuario.md](docs/sprints-historias-usuario.md) — aquí solo se registra el **estado**, no se repite el contenido.

---

## ▶ Siguiente HU a ejecutar

**HU-01 — Test de regresión del contrato de salida (golden JSON)** — Sprint 1

*(Este bloque se actualiza cada vez que se completa una HU, apuntando a la siguiente en el orden de la tabla de abajo.)*

---

## Flujo de Git

**Commit directo a `main`** en https://github.com/lemarunico2020/Heroku_PhishProtect. Al completar cada HU (tests + seguridad en verde) se hace commit y push directo a `main`, con mensaje que referencia el ID de la HU (ej. `HU-02: activar de-fanging de IOCs con ioc-fanger`). No se abren ramas ni PRs para este flujo.

## Tabla de avance

Leyenda: `Pendiente` · `En progreso` · `Bloqueada` · `Hecha`

| # | HU | Sprint | Título | Estado | Fecha | Commit | Notas |
|---|----|--------|--------|--------|-------|--------|-------|
| 1 | HU-01 | 1 | Test de regresión del contrato de salida | Pendiente | — | — | Bloquea al resto: valida que ninguna HU rompa el JSON de n8n |
| 2 | HU-02 | 1 | Activar de-fanging de IOCs con `ioc-fanger` | Pendiente | — | — | |
| 3 | HU-03 | 1 | Allowlist configurable de dominios y correos | Pendiente | — | — | |
| 4 | HU-04 | 1 | Logging configurable por entorno y sin datos sensibles | Pendiente | — | — | |
| 5 | HU-05 | 2 | Extraer IP del primer salto en `Received` | Pendiente | — | — | |
| 6 | HU-06 | 2 | Extracción de texto de adjuntos TXT/HTML | Pendiente | — | — | |
| 7 | HU-07 | 2 | Extracción de texto de adjuntos PDF (stretch) | Pendiente | — | — | Mover a Sprint 3 si Sprint 2 se satura |
| 8 | HU-08 | 3 | Diseño del esquema `ml_features` | Pendiente | — | — | Requiere revisión/aprobación del esquema antes de HU-09/HU-10 |
| 9 | HU-09 | 3 | Features de autenticación y remitente | Pendiente | — | — | |
| 10 | HU-10 | 3 | Features de contenido (urgencia, conteos, adjuntos ejecutables) | Pendiente | — | — | |
| 11 | HU-11 | 4 | Tuning de gunicorn y límites de recursos | Pendiente | — | — | |
| 12 | HU-12 | 4 | Refactor de `app.py` en módulos + `hmac.compare_digest` en API Key | Pendiente | — | — | Incluye corrección de timing attack detectada |
| 13 | HU-13 | 4 | Dockerfile y despliegue en EasyPanel | Pendiente | — | — | |

**Progreso:** 0 / 13 HU completadas (0%)

---

## Backlog futuro (no forma parte de este seguimiento)

- Persistencia de resultados en base de datos — a cargo del usuario.
- Enriquecimiento externo (VirusTotal, AbuseIPDB, WHOIS).
- Cola asíncrona (Celery/RQ + Redis).
- CI/CD con pipeline de seguridad automatizado.

---

## Protocolo de actualización de este archivo

Al completar una HU:

1. Confirmar que se cumplió el checklist de DoD de la HU (tests en `venv`, `bandit`, `pip-audit`, y que el test de contrato de salida de HU-01 sigue en verde).
2. Hacer commit y push directo a `main` con mensaje que referencie el ID de la HU (ej. `HU-02: activar de-fanging de IOCs con ioc-fanger`). Nunca se hace commit/push sin haber cumplido el paso 1.
3. Cambiar su fila en la tabla: `Estado` → `Hecha`, `Fecha` → fecha real (YYYY-MM-DD), `Commit` → hash corto del commit (ej. `a1b2c3d`), y en `Notas` dejar un resumen de una línea de lo implementado (archivos tocados, decisiones relevantes) o cualquier desviación respecto a lo descrito en `docs/sprints-historias-usuario.md`.
4. Actualizar el contador **Progreso** (`X / 13`).
5. Actualizar el bloque **▶ Siguiente HU a ejecutar** con la siguiente fila en estado `Pendiente` de la tabla (respetando el orden de sprints).
6. Si una HU queda bloqueada (por ejemplo, depende de una decisión del usuario), marcarla como `Bloqueada` y anotar en `Notas` qué falta para desbloquearla — y dejar el bloque **▶ Siguiente HU a ejecutar** apuntando a la próxima HU no bloqueada.
7. Si se decide saltar o reordenar una HU, dejarlo anotado en `Notas` con el motivo, sin borrar la fila (mantener trazabilidad completa del avance real vs. el plan original).
