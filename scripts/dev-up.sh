#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required." >&2
  exit 1
fi

if [ ! -f .env ]; then
  python - <<'PY'
import base64
import secrets
from pathlib import Path

def secret():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")

values = [
    "APP_ENV=development",
    "REGISTRATION_MODE=open",
    "POSTGRES_PASSWORD=" + secrets.token_urlsafe(32),
    "KEK_V1=" + secret(),
    "RATE_LIMIT_PEPPER_V1=" + secret(),
    "ITEM_TTL_DAYS=30",
    "BACKUP_RETENTION_DAYS=30",
    "USER_STORAGE_LIMIT_BYTES=104857600",
]
path = Path(".env")
path.write_text("\n".join(values) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
  echo "Created .env with local-only cryptographic secrets (mode 600). Keep it private."
fi

docker compose up --build -d
published_address=$(docker compose port gateway 80 | head -n 1)
http_port=${published_address##*:}
echo "SecureBox is starting at http://localhost:${http_port}"
echo "Check readiness with: docker compose ps"
