from __future__ import annotations

import hashlib
import json
from typing import Literal

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...crypto import CryptoError
from ...database import get_db
from ...models import Item
from ...security import Principal
from ..dependencies import _csrf, _principal, _rate
from ..errors import _deny
from ..schemas import ProfileInput
from ...services.items import _queue_item, _variant_plaintext

router = APIRouter(prefix="/api/v1")

@router.put("/me/profile", status_code=202)
def update_profile(body: ProfileInput, request: Request, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(_principal)):
    _csrf(request, db, settings, principal, csrf_token)
    _rate(db, settings, "user:" + principal.user_id, "upload", 5, 60)
    payload = body.model_dump(exclude_none=True)
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > 64 * 1024:
        _deny(413, "file_too_large")
    metadata = {"original_filename": "Profile snapshot", "content_type": "application/json", "kind": "profile", "sha256": hashlib.sha256(data).hexdigest()}
    item, job = _queue_item(db, settings, request.app.state.store, principal, "profile", data, metadata)
    return {"item_id": item.id, "job_id": job.id, "status": "queued"}


@router.get("/me/profile")
def read_profile(request: Request, algorithm: Literal["aes", "des", "rc4"] = Query(default="aes"), principal: Principal = Depends(_principal), db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    item = db.scalar(select(Item).where(Item.owner_id == principal.user_id, Item.kind == "profile", Item.status == "complete").order_by(Item.created_at.desc()).limit(1))
    if not item:
        _deny(404, "profile_not_found")
    try:
        plaintext = _variant_plaintext(item, algorithm, db, settings, request.app.state.store, request.app.state.crypto)
        return {"algorithm": algorithm, "profile": json.loads(plaintext)}
    except (CryptoError, ValueError, json.JSONDecodeError):
        _deny(500, "internal_error")
