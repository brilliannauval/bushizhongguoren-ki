from __future__ import annotations

import hashlib
import hmac
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..crypto import CryptoError, CryptoProvider
from ..domain.errors import DomainError
from ..error_messages import error_message
from ..envelope import (
    metadata_aad,
    open_metadata,
    open_payload,
    seal_metadata,
    seal_payload,
    staging_aad,
    unpack_inner_material,
    variant_aad,
)
from ..models import CipherVariant, Item, Job, User, UserWorkSlot
from ..security import Principal
from ..storage import PrivateObjectStore
from ..jobs.common import enqueue_object_cleanup


def _queue_item(db: Session, settings: Settings, store: PrivateObjectStore, principal: Principal, kind: str, data: bytes, metadata: dict) -> tuple[Item, Job]:
    user = db.scalar(
        select(User)
        .where(User.id == principal.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not user or user.deleted_at is not None:
        raise DomainError("not_found")
    if db.get(UserWorkSlot, principal.user_id):
        raise DomainError("active_job_exists")
    used = db.scalar(select(func.coalesce(func.sum(Item.original_size), 0)).where(Item.owner_id == principal.user_id, Item.status != "deleted")) or 0
    if used + len(data) > settings.user_storage_limit_bytes:
        raise DomainError("storage_quota_exceeded")
    item_id, job_id, stage_key = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    metadata_envelope = seal_metadata(metadata, settings.kek_v1, metadata_aad(principal.user_id, item_id))
    staged, wrapped = seal_payload(data, settings.kek_v1, staging_aad(principal.user_id, item_id))
    store.put(stage_key, staged)
    item = Item(id=item_id, owner_id=principal.user_id, kind=kind, status="queued", original_size=len(data), metadata_envelope=metadata_envelope)
    job = Job(id=job_id, item_id=item_id, owner_id=principal.user_id, state="queued", staging_object_key=stage_key, staging_wrapped_dek=wrapped, idempotency_key=str(uuid.uuid4()))
    try:
        db.add_all((item, job, UserWorkSlot(owner_id=principal.user_id, work_id=job_id, work_type="upload")))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        try:
            store.delete(stage_key)
        except Exception:
            from ..database import SessionLocal

            with SessionLocal() as cleanup:
                enqueue_object_cleanup(cleanup, [stage_key], principal.user_id)
                cleanup.commit()
        raise DomainError("active_job_exists") from exc
    except Exception:
        db.rollback()
        try:
            store.delete(stage_key)
        except Exception:
            from ..database import SessionLocal

            with SessionLocal() as cleanup:
                enqueue_object_cleanup(cleanup, [stage_key], principal.user_id)
                cleanup.commit()
        raise
    return item, job


def _owned_item(db: Session, principal: Principal, item_id: str) -> Item:
    item = db.scalar(select(Item).where(Item.id == item_id, Item.owner_id == principal.user_id, Item.status != "deleted"))
    if not item:
        raise DomainError("not_found")
    return item


def _metadata(item: Item, settings: Settings) -> dict:
    return open_metadata(item.metadata_envelope, settings.kek_v1, metadata_aad(item.owner_id, item.id))


def _item_json(item: Item, settings: Settings) -> dict:
    metadata = _metadata(item, settings)
    error_code = item.job.error_code if item.status == "failed" and item.job else None
    return {
        "id": item.id,
        "kind": item.kind,
        "name": metadata.get("original_filename", "Profile snapshot"),
        "content_type": metadata.get("content_type", "application/json"),
        "size_bytes": item.original_size,
        "status": item.status,
        "error_message": error_message(error_code) if error_code else None,
        "created_at": item.created_at.isoformat(),
    }


def _variant_plaintext(item: Item, algorithm: str, db: Session, settings: Settings, store: PrivateObjectStore, crypto: CryptoProvider) -> bytes:
    variant = db.scalar(select(CipherVariant).where(CipherVariant.item_id == item.id, CipherVariant.algorithm == algorithm))
    if not variant:
        raise DomainError("invalid_state")
    packed = open_payload(
        store.get(variant.object_key),
        variant.wrapped_dek,
        settings.kek_v1,
        variant_aad(item.owner_id, item.id, variant.algorithm, variant.mode, variant.crypto_version),
    )
    key, iv, ciphertext = unpack_inner_material(packed)
    plaintext, _ = crypto.decrypt(algorithm, ciphertext, key, iv, "pycryptodome")
    expected = _metadata(item, settings).get("sha256", "")
    if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), expected):
        raise CryptoError("Stored content integrity check failed")
    return plaintext
