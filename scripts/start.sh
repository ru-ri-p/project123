#!/usr/bin/env sh
# Web service entrypoint: apply migrations, then serve the API.
# Migrations run on boot so a fresh database is brought to head automatically.
# (Single-instance pilot; for multi-instance, move migrations to a release step.)
set -e

echo "[start] alembic upgrade head"
alembic upgrade head

PORT="${PORT:-8000}"
echo "[start] uvicorn app.main:app on 0.0.0.0:${PORT}"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
