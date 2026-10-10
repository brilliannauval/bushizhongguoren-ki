# SecureBox

SecureBox is an educational web application for saving a user's profile and files, then comparing three legacy cipher implementations. It combines a static browser interface with a versioned FastAPI API, background processing, and private object storage.

**Use synthetic data only.** The project is an assignment/demo, not a production personal-data service, end-to-end encrypted vault, or legal-compliance certification. Do not upload real ID cards, account credentials, or other sensitive information. RC4 and DES are obsolete and are included for comparison only.

## Features

- Local account registration, sign-in, profile snapshots, and account deletion.
- Owner-scoped file upload, listing, ciphertext preview/download, and deletion.
- Background jobs create AES, DES, and RC4 comparison variants and report benchmark results.
- The browser UI is served by FastAPI; the API is versioned under `/api/v1`.
- Local development uses PostgreSQL and a private Docker volume. Production configuration requires PostgreSQL and private S3-compatible object storage.
- Input checks validate the filename, extension, declared MIME type, file signature, and relevant document structure before processing.

### Data handled by the demo

The app stores account usernames and password verifiers, session/security metadata, optional profile fields (contact email, phone, address, date of birth, and national ID), uploaded files, and job/benchmark metadata. Identity cards and uploaded documents can contain highly sensitive personal information even when the rest of the app is configured securely. Use fabricated values and sample files only.

## Tech Stack

| Area | Technology |
|---|---|
| API and app server | Python 3.13 container, FastAPI, Starlette, Uvicorn |
| Browser UI | HTML, CSS, and JavaScript; no frontend build step |
| Database and migrations | PostgreSQL 16 in local Compose, SQLAlchemy, Alembic |
| Local gateway | NGINX in Docker Compose; it proxies requests to FastAPI |
| File storage | Private local object directory for development, private S3-compatible bucket for deployment |
| Cryptography | x86-64 assembly routines with PyCryptodome as a labeled fallback; PyCryptodome also provides AES-GCM envelopes |
| File validation | Pillow for images, pypdf for PDFs, bounded ZIP/XML checks for DOCX/XLSX, and `ffprobe` for MP4 |
| Tests | pytest and FastAPI/httpx test clients |

The Docker image compiles the native shared library from the assembly source. The generated `libcrypto_asm.so` is a build artifact; keep the source files and `Makefile` in version control instead.

## How the application is arranged

```text
Browser
  ├── local: NGINX gateway ── FastAPI
  └── hosted: provider HTTPS ingress ── FastAPI
                                    ├── PostgreSQL: accounts, metadata, jobs
                                    ├── private object store: encrypted objects
                                    └── background worker ── isolated crypto subprocess
```

In the local Compose setup, NGINX is the only published container. FastAPI serves the UI and API behind it. In the Render template, FastAPI is served directly behind Render's HTTPS ingress. The worker runs with the FastAPI service and uses database-backed job records. The cryptography routines run in a separate child process so a native fault can be contained and the operation retried with the labeled Python backend.

### Project structure

```text
securebox/
  api/                 Routes, request schemas, auth dependencies, middleware, errors
  domain/              Domain-level errors
  jobs/                Upload, benchmark, expiry, and cleanup worker logic
  services/            Reusable item/profile operations
  static/              Browser UI, privacy page, styles, and JavaScript
  crypto_asm/          Assembly source, Python bindings, and Makefile
  config.py            Environment configuration and startup validation
  crypto.py            Backend selection, subprocess isolation, fallback, benchmarks
  database.py          SQLAlchemy engine and database sessions
  envelope.py          AES-GCM object/metadata envelopes and key wrapping
  main.py              FastAPI application composition and static UI mounting
  models.py            Database models
  security.py          Password/session and rate-limit helpers
  storage.py           Private local or S3-compatible object storage
  validation.py        Upload validation
migrations/            Alembic migration environment and schema revisions
nginx/                 Local reverse-proxy configuration
scripts/               Local startup and container entrypoint scripts
tests/                 API, validation, crypto, readiness, and security tests
Dockerfile             Multi-stage image build; compiles assembly in the build stage
compose.yaml           Local PostgreSQL, FastAPI, and NGINX services
render.yaml            Render Docker web-service template
requirements.txt       Pinned Python dependencies
alembic.ini            Alembic configuration
pytest.ini             pytest configuration
```

## Encryption model and limitations

For each accepted file or profile snapshot, the worker creates three comparison variants:

| Label | Comparison algorithm |
|---|---|
| AES | AES-128-CBC with PKCS#7 padding |
| DES | DES-CBC with PKCS#7 padding |
| RC4 | RC4 stream cipher |

The comparison ciphertext, its algorithm key/IV material, temporary upload data, and private metadata are protected with AES-256-GCM. Payload envelopes use a random data-encryption key wrapped by `KEK_V1`; metadata is encrypted directly with `KEK_V1`. This authenticated layer protects stored bytes and metadata. The application server holds the wrapping key and processes plaintext, so this is **not end-to-end encryption**.

AES-CBC by itself does not authenticate ciphertext. DES and RC4 are broken/obsolete choices and must not protect real data. Do not use benchmark results as a security comparison. Assembly is used only when the runtime is Linux x86-64, the required AES-NI/SSE4.1 CPU flags are present, and native known-answer checks pass. Otherwise the app uses PyCryptodome and labels the backend. A successful image build does not prove the deployment CPU supports the assembly path; check `/api/v1/health` and its `assembly_ready`, `assembly_status`, and `crypto_backend` values before presenting assembly measurements.

### Accepted uploads

The extension, MIME type, and actual file structure must agree. The app applies these per-file caps:

| Type | Extensions | Maximum size |
|---|---|---:|
| Image | `.jpg`, `.jpeg`, `.png` | 5 MiB |
| PDF | `.pdf` | 10 MiB |
| Word | `.docx` | 10 MiB |
| Excel | `.xlsx` | 10 MiB |
| Video | `.mp4` | 20 MiB |

MP4 validation requires `ffprobe`; the current checks also limit video duration to 10 minutes and dimensions to 1920×1080. Office documents are checked for unsafe/external content and archive expansion limits. Profile snapshots are limited to 64 KiB. A configurable total upload limit and per-user storage quota may impose lower limits.

## Run locally with Docker

### Requirements

- Docker Engine or Docker Desktop with Docker Compose v2.
- A shell that can run the repository scripts. On Windows, use WSL2 or another Unix-compatible shell.
- An x86-64 Docker build environment: the current Dockerfile compiles x86-64 assembly and is not an ARM-native image build.

From the project root, start the full stack:

```sh
./scripts/dev-up.sh
```

On its first run, the script creates a private, mode-600 `.env` with local database and application secrets, then builds and starts PostgreSQL, FastAPI, and NGINX. The default browser address is [http://localhost:8080](http://localhost:8080); the script prints the actual address if you configure another port. Local registration is open for convenience. Use synthetic data only.

Useful commands:

```sh
docker compose ps
docker compose logs -f securebox
docker compose down
```

`docker compose down` keeps the database and file volumes. To permanently erase local demo data as well, run `docker compose down --volumes`. If port 8080 is already occupied, set `SECUREBOX_HTTP_PORT=8081` in the local `.env` and run `docker compose up --build -d` again.

The local stack stores PostgreSQL and objects in Docker volumes. Keep those volumes and `.env` private. If Docker reports an overlapping subnet, set `SECUREBOX_DOCKER_SUBNET`, `SECUREBOX_GATEWAY_IP`, `SECUREBOX_APP_IP`, and `SECUREBOX_DB_IP` in `.env` to an unused private subnet and addresses within it.

## Run directly with Python (optional)

This route is useful for code changes. For the complete local feature set, use Python 3.12+, Linux x86-64, GNU Make/GCC, and FFmpeg (which provides `ffprobe`). Windows users can use WSL2. On unsupported CPU/OS combinations, the application can use the PyCryptodome fallback; the assembly build itself targets Linux x86-64.

On Ubuntu/WSL, install system tools, create a virtual environment, install Python packages, and build the native library:

```sh
sudo apt-get update
sudo apt-get install -y build-essential ffmpeg
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
make -C securebox/crypto_asm
```

Configure a local SQLite database and object directory. Generate and keep stable development keys if you want existing local objects to remain readable after restarting the app:

```sh
mkdir -p var/objects
export APP_ENV=development
export DATABASE_URL=sqlite:///./var/securebox.db
export OBJECT_DIR=./var/objects
export KEK_V1="$(python -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"
export RATE_LIMIT_PEPPER_V1="$(python -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')"
alembic upgrade head
uvicorn securebox.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). In development, missing `KEK_V1` and `RATE_LIMIT_PEPPER_V1` are generated temporarily at startup; encrypted data may become unreadable after a restart if you do not set persistent values. Keep local database and object files private.

## Configuration reference

Docker Compose supplies the development settings. For manual development or a hosted deployment, the app reads these environment variables:

| Variable | Purpose and requirement |
|---|---|
| `APP_ENV` | Use `development` locally and `production` for deployment. |
| `DATABASE_URL` | Defaults to local SQLite in development. Production requires PostgreSQL; TLS is required by the application. |
| `OBJECT_DIR` | Local private object directory; defaults to `./var/objects`. Production must use a private S3-compatible bucket instead of local disk. |
| `KEK_V1` | Persistent base64url encoding of exactly 32 random bytes. Required outside development. Back it up separately from database/object backups; losing or rotating it without migration makes stored data unreadable. |
| `RATE_LIMIT_PEPPER_V1` | Persistent base64url encoding of exactly 32 random bytes. Required outside development. |
| `REGISTRATION_MODE` | `open`, `invite`, or `closed`; defaults to `open` in development and `invite` otherwise. Public deployment rejects open registration. |
| `INVITATION_CODE` | Required when production registration is `invite`. |
| `PUBLIC_ORIGIN` | Required outside development and must be the public HTTPS origin, such as `https://example.com`. |
| `S3_ENDPOINT_URL` / `R2_ENDPOINT` | S3-compatible endpoint. `R2_ENDPOINT` is supported as an alias. |
| `S3_BUCKET` / `R2_BUCKET` | Private bucket name. Bucket and access credentials must be configured together in production. |
| `S3_ACCESS_KEY_ID` / `R2_ACCESS_KEY_ID` | Restricted server-side bucket credential; `R2_*` names are supported aliases. |
| `S3_SECRET_ACCESS_KEY` / `R2_SECRET_ACCESS_KEY` | Secret part of the restricted bucket credential; `R2_*` names are supported aliases. |
| `S3_REGION` | S3 region; defaults to `auto`, suitable for providers such as R2. |
| `MAX_UPLOAD_BYTES` | Global upload cap; defaults to 20 MiB. Per-format limits in this README still apply. |
| `USER_STORAGE_LIMIT_BYTES` | Per-user storage limit; defaults to 100 MiB. |
| `ITEM_TTL_DAYS` | Item retention period; defaults to 30 days. |
| `BACKUP_RETENTION_DAYS` | Retention value shown in the privacy information; defaults to 30 days. The app does not create or schedule backups. |
| `CONTROLLER_NAME`, `PRIVACY_CONTACT` | Required outside development so the privacy page identifies the data controller and contact. |

Never commit populated environment files, credentials, wrapping keys, or database/object data. Set production values through the hosting provider's secret/environment settings.

## API and testing

- Interactive OpenAPI: `/api/docs`
- OpenAPI JSON: `/api/openapi.json`
- Readiness and runtime crypto status: `/api/v1/health`
- Public runtime and privacy information: `/api/v1/config`, `/api/v1/privacy`
- Main API groups: `/api/v1/auth/*`, `/api/v1/me`, `/api/v1/me/profile`, `/api/v1/files`, `/api/v1/items/*`, `/api/v1/jobs/*`, and `/api/v1/benchmark-runs/*`.

The API uses same-origin session cookies and CSRF checks for state-changing browser requests. User records and objects are owner-scoped. Passwords are stored as password verifiers, not plaintext. Do not put private data or secrets in issue reports, screenshots, or logs.

Run the test suite from the repository root after installing `requirements.txt`:

```sh
python -m pytest -q
```
