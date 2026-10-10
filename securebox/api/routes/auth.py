from __future__ import annotations

import hmac
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...database import get_db
from ...models import BenchmarkRun, Item, SessionRecord, User, UserWorkSlot
from ...security import (
    SESSION_COOKIE,
    Principal,
    authenticate_session,
    create_session,
    get_rate_count,
    password_hash,
    renew_csrf,
    revoke_session,
    utcnow,
    username_normalize,
    verify_password,
)
from ..dependencies import _csrf, _network, _principal, _rate
from ..errors import ApiError, _deny
from ..schemas import LoginRequest, RegisterRequest
from ...jobs.common import enqueue_object_cleanup

router = APIRouter(prefix="/api/v1")

@router.get("/auth/session")
def auth_session(request: Request, db: Session = Depends(get_db)):
    session_token = request.cookies.get(SESSION_COOKIE)
    principal = authenticate_session(db, session_token)
    if not principal:
        return {"authenticated": False}
    user = db.get(User, principal.user_id)
    token = renew_csrf(db, principal, session_token)
    db.commit()
    return {"authenticated": True, "username": user.username, "csrf_token": token}


@router.post("/auth/register", status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    _rate(db, settings, _network(request), "register", 3, 3600)
    if settings.registration_mode == "closed":
        _deny(403, "registration_closed")
    if settings.registration_mode == "invite":
        wanted, received = settings.invitation_code or "", body.invitation_code or ""
        if not wanted or not hmac.compare_digest(wanted.encode(), received.encode()):
            _deny(403, "invalid_invitation")
    try:
        username, hashed = username_normalize(body.username), password_hash(body.password)
    except ValueError as exc:
        raise ApiError(422, "invalid_request") from exc
    if db.scalar(select(User.id).where(User.username == username)):
        _deny(409, "registration_conflict")
    db.add(User(username=username, password_hash=hashed))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ApiError(409, "registration_conflict") from exc
    return {"created": True}


_DUMMY_HASH = password_hash("SecureBox timing-only dummy password")


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    network = _network(request)
    _rate(db, settings, network, "login-network", 30, 900)
    normalized = body.username.strip().lower()[:128]
    subject = "login:" + normalized + ":" + network
    failures, retry = get_rate_count(db, settings, subject, "login-fail", 900)
    if failures >= 5:
        raise HTTPException(429, detail={"code": "rate_limited"}, headers={"Retry-After": str(retry)})
    user = db.scalar(select(User).where(User.username == normalized, User.deleted_at.is_(None)))
    valid = verify_password(user.password_hash, body.password) if user else verify_password(_DUMMY_HASH, body.password)
    if not user or not valid:
        _rate(db, settings, subject, "login-fail", 5, 900)
        _deny(401, "invalid_credentials")
    token, csrf, _record = create_session(db, user)
    db.commit()
    response.set_cookie(SESSION_COOKIE, token, max_age=86400, httponly=True, secure=settings.app_env != "development", samesite="lax", path="/")
    return {"authenticated": True, "username": user.username, "csrf_token": csrf}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(_principal)):
    _csrf(request, db, settings, principal, csrf_token)
    revoke_session(db, principal)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.app_env != "development", httponly=True, samesite="lax")
    # Let FastAPI emit the injected response (including the cleared cookie) with
    # the route's 204 status instead of returning that response object as data.
    return None


@router.get("/me")
def me(principal: Principal = Depends(_principal)):
    return {"username": principal.username}


@router.delete("/me", status_code=204)
def delete_me(
    request: Request,
    response: Response,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(_principal),
):
    _csrf(request, db, settings, principal, csrf_token)
    user = db.scalar(
        select(User)
        .where(User.id == principal.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not user or user.deleted_at is not None:
        _deny(401, "unauthenticated")

    items = db.scalars(select(Item).where(Item.owner_id == user.id).with_for_update()).all()
    object_keys: list[str] = []
    active_work_ids: set[str] = set()
    for item in items:
        item.status = "deleted"
        object_keys.extend(variant.object_key for variant in item.variants)
        if item.job:
            if item.job.staging_object_key:
                object_keys.append(item.job.staging_object_key)
            if item.job.state == "processing":
                active_work_ids.add(item.job.id)
            else:
                item.job.state = "deleted"
                item.job.error_code = None
                item.job.lease_until = None

    runs = db.scalars(select(BenchmarkRun).where(BenchmarkRun.owner_id == user.id).with_for_update()).all()
    for run in runs:
        if run.state == "processing":
            active_work_ids.add(run.id)
        else:
            run.state = "deleted"
            run.error_code = None
            run.lease_until = None
            run.result_json = None

    enqueue_object_cleanup(db, object_keys, user.id)
    slot = db.get(UserWorkSlot, user.id)
    if slot and slot.work_id not in active_work_ids:
        db.delete(slot)
    db.execute(delete(SessionRecord).where(SessionRecord.user_id == user.id))

    user.deleted_at = utcnow()
    user.username = f"deleted-{user.id.replace('-', '')[:24]}"
    user.password_hash = "!deleted!"
    db.commit()
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=settings.app_env != "development",
        httponly=True,
        samesite="lax",
    )
    return None
