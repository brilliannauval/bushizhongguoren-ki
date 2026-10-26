from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..database import get_db
from ..security import (
    SESSION_COOKIE,
    Principal,
    authenticate_session,
    check_rate_limit,
    verify_csrf,
)
from .errors import _deny

def _rate(db: Session, settings: Settings, subject: str, action: str, limit: int, seconds: int):
    allowed, retry = check_rate_limit(db, settings, subject, action, limit, seconds)
    db.commit()
    if not allowed:
        raise HTTPException(429, detail={"code": "rate_limited"}, headers={"Retry-After": str(retry)})


def _network(request: Request) -> str:
    return "network:" + (request.client.host if request.client else "unknown")


def _origin_matches(request: Request, settings: Settings) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return False
    expected = settings.public_origin.rstrip("/") if settings.public_origin else f"{request.url.scheme}://{request.headers.get('host', '')}".rstrip("/")
    return hmac.compare_digest(origin.rstrip("/"), expected)


def _csrf(request: Request, db: Session, settings: Settings, principal: Principal, token: str | None):
    if not _origin_matches(request, settings) or not verify_csrf(db, principal, token):
        _deny(403, "session_check_failed")


def _principal(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    principal = authenticate_session(db, request.cookies.get(SESSION_COOKIE))
    if not principal:
        _deny(401, "unauthenticated")
    _rate(db, settings, "user:" + principal.user_id, "api", 60, 60)
    db.commit()  # persists last-used and session activity timestamps
    return principal
