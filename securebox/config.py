from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit


def _decode_secret(value: str | None, name: str, *, allow_ephemeral: bool) -> bytes:
    if not value:
        if not allow_ephemeral:
            raise RuntimeError(f"{name} must be configured outside development")
        return secrets.token_bytes(32)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise RuntimeError(f"{name} must be base64url encoded") from exc
    if len(raw) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes")
    return raw


def _validate_public_origin(value: str | None, *, development: bool) -> str | None:
    if not value:
        if development:
            return None
        raise RuntimeError("PUBLIC_ORIGIN must be configured outside development")
    try:
        parsed = urlsplit(value.rstrip("/"))
        _ = parsed.port  # Validate numeric/range syntax as well as the hostname.
    except ValueError as exc:
        raise RuntimeError("PUBLIC_ORIGIN must be a valid origin URL") from exc
    allowed_schemes = {"https"} if not development else {"http", "https"}
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("PUBLIC_ORIGIN must contain only the public scheme, host, and optional port")
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    app_env: str
    database_url: str
    object_dir: Path
    kek_v1: bytes
    rate_limit_pepper_v1: bytes
    registration_mode: str
    invitation_code: str | None
    public_origin: str | None
    max_upload_bytes: int
    user_storage_limit_bytes: int
    item_ttl_days: int
    s3_endpoint_url: str | None
    s3_bucket: str | None
    s3_access_key_id: str | None
    s3_secret_access_key: str | None
    s3_region: str | None
    controller_name: str
    privacy_contact: str
    backup_retention_days: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    app_env = os.getenv("APP_ENV", "production").lower()
    development = app_env == "development"
    object_dir = Path(os.getenv("OBJECT_DIR", "./var/objects")).resolve()
    database_url = os.getenv("DATABASE_URL", "sqlite:///./var/securebox.db")
    registration_mode = os.getenv("REGISTRATION_MODE", "open" if development else "invite")
    if registration_mode not in {"open", "invite", "closed"}:
        raise RuntimeError("REGISTRATION_MODE must be open, invite, or closed")
    if not development and registration_mode == "open":
        raise RuntimeError("Public registration must be invite-only or closed")

    settings = Settings(
        app_env=app_env,
        database_url=database_url,
        object_dir=object_dir,
        kek_v1=_decode_secret(os.getenv("KEK_V1"), "KEK_V1", allow_ephemeral=development),
        rate_limit_pepper_v1=_decode_secret(
            os.getenv("RATE_LIMIT_PEPPER_V1"), "RATE_LIMIT_PEPPER_V1", allow_ephemeral=development
        ),
        registration_mode=registration_mode,
        invitation_code=os.getenv("INVITATION_CODE"),
        public_origin=_validate_public_origin(os.getenv("PUBLIC_ORIGIN"), development=development),
        max_upload_bytes=int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024))),
        user_storage_limit_bytes=int(os.getenv("USER_STORAGE_LIMIT_BYTES", str(100 * 1024 * 1024))),
        item_ttl_days=int(os.getenv("ITEM_TTL_DAYS", "30")),
        s3_endpoint_url=os.getenv("S3_ENDPOINT_URL") or os.getenv("R2_ENDPOINT"),
        s3_bucket=os.getenv("S3_BUCKET") or os.getenv("R2_BUCKET"),
        s3_access_key_id=os.getenv("S3_ACCESS_KEY_ID") or os.getenv("R2_ACCESS_KEY_ID"),
        s3_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY") or os.getenv("R2_SECRET_ACCESS_KEY"),
        s3_region=os.getenv("S3_REGION", "auto"),
        controller_name=os.getenv("CONTROLLER_NAME", "SecureBox assignment team" if development else ""),
        privacy_contact=os.getenv("PRIVACY_CONTACT", "Set a contact address before accepting demo users" if development else ""),
        backup_retention_days=int(os.getenv("BACKUP_RETENTION_DAYS", "30")),
    )
    if not development and database_url.startswith("sqlite:"):
        raise RuntimeError("SQLite is development-only; configure PostgreSQL for deployment")
    if not development and not settings.s3_bucket:
        raise RuntimeError("Configure a private S3-compatible bucket for deployment")
    if not development and registration_mode == "invite" and not settings.invitation_code:
        raise RuntimeError("Configure an invitation code when registration is invite-only")
    if not development and (not settings.controller_name or not settings.privacy_contact):
        raise RuntimeError("Configure the data controller name and privacy contact before deployment")
    if bool(settings.s3_bucket) != bool(settings.s3_access_key_id and settings.s3_secret_access_key):
        raise RuntimeError("S3 bucket and credentials must be configured together")
    return settings
