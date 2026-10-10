from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import Response as FastAPIResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from ...config import Settings, get_settings
from ...crypto import CryptoError
from ...database import get_db
from ...envelope import open_payload, unpack_inner_material, variant_aad
from ...jobs import ALGORITHMS
from ...jobs.common import enqueue_object_cleanup
from ...models import BenchmarkRun, CipherVariant, Item, User, UserWorkSlot
from ...security import Principal
from ...validation import InvalidUpload, validate_file
from ..dependencies import _csrf, _network, _principal, _rate
from ..errors import ApiError, ERROR_MESSAGES, _deny
from ...services.items import _item_json, _metadata, _owned_item, _queue_item, _variant_plaintext

router = APIRouter(prefix="/api/v1")

@router.get("/items")
def list_items(cursor: str | None = Query(default=None, max_length=96), limit: int = Query(default=20, ge=1, le=50), principal: Principal = Depends(_principal), db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    query = select(Item).where(Item.owner_id == principal.user_id, Item.status != "deleted")
    if cursor:
        try:
            created_text, item_id = cursor.split("~", 1)
            created = datetime.fromisoformat(created_text)
            created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created.astimezone(timezone.utc)
            if not re.fullmatch(r"[a-f0-9-]{36}", item_id):
                raise ValueError()
        except ValueError as exc:
            raise ApiError(400, "invalid_request") from exc
        query = query.where(or_(Item.created_at < created, (Item.created_at == created) & (Item.id < item_id)))
    rows = db.scalars(query.order_by(Item.created_at.desc(), Item.id.desc()).limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = f"{rows[-1].created_at.isoformat()}~{rows[-1].id}" if more and rows else None
    return {"items": [_item_json(item, settings) for item in rows], "next_cursor": next_cursor}


@router.get("/items/{item_id}")
def get_item(item_id: str, principal: Principal = Depends(_principal), db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    return _item_json(_owned_item(db, principal, item_id), settings)


@router.get("/items/{item_id}/variants")
def list_variants(item_id: str, principal: Principal = Depends(_principal), db: Session = Depends(get_db)):
    item = _owned_item(db, principal, item_id)
    rows = db.scalars(select(CipherVariant).where(CipherVariant.item_id == item.id)).all() if item.status == "complete" else []
    rows.sort(key=lambda value: ALGORITHMS.index(value.algorithm))
    return {"item_id": item.id, "status": item.status, "variants": [{"algorithm": row.algorithm, "mode": row.mode, "backend": row.backend, "version": row.crypto_version, "ciphertext_bytes": row.byte_count, "sha256": row.digest_sha256, "encryption_ms": round(row.encrypt_ms, 4)} for row in rows]}


@router.get("/items/{item_id}/variants/{algorithm}/ciphertext")
def ciphertext_preview(item_id: str, algorithm: Literal["aes", "des", "rc4"], request: Request, principal: Principal = Depends(_principal), db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    item = _owned_item(db, principal, item_id)
    if item.status != "complete":
        _deny(409, "invalid_state")
    variant = db.scalar(select(CipherVariant).where(CipherVariant.item_id == item.id, CipherVariant.algorithm == algorithm))
    if not variant:
        _deny(404, "not_found")
    packed = open_payload(
        request.app.state.store.get(variant.object_key),
        variant.wrapped_dek,
        settings.kek_v1,
        variant_aad(item.owner_id, item.id, variant.algorithm, variant.mode, variant.crypto_version),
    )
    _key, _iv, ciphertext = unpack_inner_material(packed)
    return {"algorithm": algorithm, "mode": variant.mode, "ciphertext_bytes": len(ciphertext), "sha256": hashlib.sha256(ciphertext).hexdigest(), "preview_base64": base64.b64encode(ciphertext[:64]).decode("ascii"), "preview_bytes": min(64, len(ciphertext))}


@router.get("/items/{item_id}/variants/{algorithm}/download")
def download_variant(item_id: str, algorithm: Literal["aes", "des", "rc4"], request: Request, principal: Principal = Depends(_principal), db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    _rate(db, settings, "user:" + principal.user_id, "download", 10, 60)
    item = _owned_item(db, principal, item_id)
    if item.status != "complete":
        _deny(409, "invalid_state")
    plaintext = _variant_plaintext(item, algorithm, db, settings, request.app.state.store, request.app.state.crypto)
    filename = _metadata(item, settings).get("original_filename", "profile.json")
    fallback = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:100] or "download"
    disposition = f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"
    return FastAPIResponse(
        plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": disposition,
            "X-Content-Type-Options": "nosniff",
            "X-Crypto-Backend": "pycryptodome",
        },
    )


@router.post("/files", status_code=202)
async def upload_file(request: Request, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(_principal)):
    _csrf(request, db, settings, principal, csrf_token)
    _rate(db, settings, _network(request), "upload-network", 20, 60)
    _rate(db, settings, "user:" + principal.user_id, "upload", 5, 60)
    form = await request.form(max_files=1, max_fields=0, max_part_size=64 * 1024)
    try:
        files = form.getlist("file")
        if set(form.keys()) != {"file"} or len(files) != 1 or not isinstance(files[0], UploadFile):
            _deny(422, "invalid_request")
        file = files[0]
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            _deny(413, "file_too_large")
        try:
            checked = await asyncio.to_thread(
                validate_file, file.filename or "", file.content_type or "", data, settings.max_upload_bytes
            )
        except InvalidUpload as exc:
            code = exc.code if exc.code in ERROR_MESSAGES else "invalid_file"
            _deny(413 if code == "file_too_large" else 415, code)
        metadata = {"original_filename": checked.display_name, "content_type": checked.mime_type, "kind": checked.kind, "sha256": hashlib.sha256(data).hexdigest()}
        item, job = _queue_item(db, settings, request.app.state.store, principal, "file", data, metadata)
        return {"item_id": item.id, "job_id": job.id, "status": "queued"}
    finally:
        await form.close()


@router.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: str, request: Request, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(_principal)):
    _csrf(request, db, settings, principal, csrf_token)
    user = db.scalar(
        select(User)
        .where(User.id == principal.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not user or user.deleted_at is not None:
        _deny(401, "unauthenticated")
    item = db.scalar(
        select(Item)
        .where(Item.id == item_id, Item.owner_id == principal.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not item:
        _deny(404, "not_found")
    keys = [variant.object_key for variant in item.variants]
    item.status = "deleted"
    if item.job:
        if item.job.staging_object_key:
            keys.append(item.job.staging_object_key)
        if item.job.state != "processing":
            item.job.state = "deleted"
            item.job.error_code = None
            item.job.lease_until = None
            slot = db.get(UserWorkSlot, principal.user_id)
            if slot and slot.work_id == item.job.id:
                db.delete(slot)
    runs = db.scalars(select(BenchmarkRun).where(BenchmarkRun.item_id == item.id).with_for_update()).all()
    for run in runs:
        if run.state != "processing":
            run.state = "deleted"
            run.error_code = None
            run.lease_until = None
            run.result_json = None
            slot = db.get(UserWorkSlot, principal.user_id)
            if slot and slot.work_id == run.id:
                db.delete(slot)
    enqueue_object_cleanup(db, keys, principal.user_id)
    db.commit()
    return Response(status_code=204)
