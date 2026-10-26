#!/bin/sh
set -eu
alembic upgrade head
exec uvicorn securebox.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1,::1}" --limit-concurrency "${MAX_CONCURRENCY:-4}"
