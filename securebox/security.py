from __future__ import annotations

import hashlib
import hmac
import base64
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import Settings
from .models import RateCounter, SessionRecord, User


PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
SESSION_COOKIE = "securebox_session"
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def username_normalize(username: str) -> str:
    normalized = username.strip().lower()
    if not USERNAME_RE.fullmatch(normalized):
        raise ValueError("Username must be 3–32 characters using letters, digits, dot, dash, or underscore")
    return normalized


def password_hash(password: str) -> str:
    if len(password) < 12 or len(password) > 128 or "\x00" in password:
        raise ValueError("Password must contain 12–128 characters")
    return PASSWORDS.hash(password)


def verify_password(hashed: str, password: str) -> bool:
    try:
        return PASSWORDS.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _digest_session(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def _csrf_for_session(session_token: str) -> str:
    digest = hmac.new(session_token.encode("ascii"), b"securebox:csrf:v1", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    session_id: str | None = None


def create_session(db: Session, user: User) -> tuple[str, str, SessionRecord]:
    token = secrets.token_urlsafe(32)
    csrf = _csrf_for_session(token)
    now = utcnow()
    record = SessionRecord(
        user_id=user.id,
        token_digest=_digest_session(token),
        csrf_digest=_digest_session(csrf),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=24),
    )
    db.add(record)
    db.flush()
    return token, csrf, record


def authenticate_session(db: Session, token: str | None) -> Principal | None:
    if not token or len(token) > 128:
        return None
    record = db.scalar(select(SessionRecord).where(SessionRecord.token_digest == _digest_session(token)))
    if record is None:
        return None
    now = utcnow()
    absolute = _aware(record.expires_at)
    idle = _aware(record.last_seen_at) + timedelta(hours=1)
    if absolute <= now or idle <= now:
        db.delete(record)
        db.flush()
        return None
    user = db.get(User, record.user_id)
    if user is None or user.deleted_at is not None:
        return None
    record.last_seen_at = now
    return Principal(user.id, user.username, session_id=record.id)


def renew_csrf(db: Session, principal: Principal, session_token: str | None = None) -> str:
    record = db.get(SessionRecord, principal.session_id) if principal.session_id else None
    if record is None or not session_token:
        raise ValueError("Session expired")
    token = _csrf_for_session(session_token)
    digest = _digest_session(token)
    if not hmac.compare_digest(record.csrf_digest, digest):
        # Existing sessions created with random CSRF tokens migrate on the
        # first session read; later reads leave the persisted digest stable.
        record.csrf_digest = digest
    return token


def verify_csrf(db: Session, principal: Principal, csrf_token: str | None) -> bool:
    if not csrf_token or len(csrf_token) > 128 or not principal.session_id:
        return False
    record = db.get(SessionRecord, principal.session_id)
    return bool(record and hmac.compare_digest(record.csrf_digest, _digest_session(csrf_token)))


def revoke_session(db: Session, principal: Principal) -> None:
    if principal.session_id:
        record = db.get(SessionRecord, principal.session_id)
        if record:
            db.delete(record)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def check_rate_limit(
    db: Session,
    settings: Settings,
    subject: str,
    action: str,
    limit: int,
    window_seconds: int,
) -> tuple[bool, int]:
    now = int(utcnow().timestamp())
    window_start = now // window_seconds * window_seconds
    digest = hmac.new(settings.rate_limit_pepper_v1, subject.encode("utf-8"), hashlib.sha256).digest()
    table = RateCounter.__table__
    values = {"subject_digest": digest, "action": action, "window_start": window_start, "count": 1}
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert

        statement = insert(table).values(**values).on_conflict_do_update(
            index_elements=[table.c.subject_digest, table.c.action, table.c.window_start],
            set_={"count": table.c.count + 1},
        ).returning(table.c.count)
        count = int(db.scalar(statement))
    elif dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert

        statement = insert(table).values(**values).on_conflict_do_update(
            index_elements=[table.c.subject_digest, table.c.action, table.c.window_start],
            set_={"count": table.c.count + 1},
        ).returning(table.c.count)
        count = int(db.scalar(statement))
    else:
        query = select(RateCounter).where(
            RateCounter.subject_digest == digest,
            RateCounter.action == action,
            RateCounter.window_start == window_start,
        ).with_for_update()
        counter = db.scalar(query)
        if counter is None:
            counter = RateCounter(**values)
            db.add(counter)
            db.flush()
        else:
            counter.count += 1
        count = counter.count
    retry_after = max(1, window_start + window_seconds - now)
    return count <= limit, retry_after


def get_rate_count(
    db: Session,
    settings: Settings,
    subject: str,
    action: str,
    window_seconds: int,
) -> tuple[int, int]:
    now = int(utcnow().timestamp())
    window_start = now // window_seconds * window_seconds
    digest = hmac.new(settings.rate_limit_pepper_v1, subject.encode("utf-8"), hashlib.sha256).digest()
    counter = db.get(RateCounter, (digest, action, window_start))
    return (counter.count if counter else 0), max(1, window_start + window_seconds - now)
