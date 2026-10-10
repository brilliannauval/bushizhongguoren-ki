from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import timedelta

from sqlalchemy import and_, or_, select, update

from ..config import Settings
from ..crypto import CryptoProvider, NativeCryptoFault
from ..database import SessionLocal
from ..envelope import (
    metadata_aad,
    open_metadata,
    open_payload,
    pack_inner_material,
    seal_payload,
    staging_aad,
    variant_aad,
)
from ..models import CipherVariant, Item, Job, User, UserWorkSlot, now_utc
from ..storage import PrivateObjectStore
from ..validation import InvalidUpload, validate_file
from .common import ALGORITHMS, MODE_BY_ALGORITHM, _release_slot, enqueue_object_cleanup

logger = logging.getLogger(__name__)


def _read_staging(job: Job, item: Item, settings: Settings, store: PrivateObjectStore) -> bytes:
    sealed = store.get(job.staging_object_key)
    return open_payload(sealed, job.staging_wrapped_dek, settings.kek_v1, staging_aad(item.owner_id, item.id))

def process_job(job_id: str, settings: Settings, store: PrivateObjectStore, crypto: CryptoProvider) -> None:
    owner_id = None
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if not job:
            return
        owner_id = job.owner_id
        now = now_utc()
        claim = update(Job).where(
            Job.id == job_id,
            or_(Job.state == "queued", and_(Job.state == "processing", Job.lease_until < now)),
            Job.attempt_count < 3,
        ).values(state="processing", attempt_count=Job.attempt_count + 1, lease_until=now + timedelta(minutes=5))
        if db.execute(claim).rowcount != 1:
            db.rollback()
            owner = db.scalar(
                select(User).where(User.id == owner_id).with_for_update().execution_options(populate_existing=True)
            )
            current_job = db.scalar(
                select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
            )
            current_item = db.scalar(
                select(Item)
                .where(Item.id == current_job.item_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ) if current_job else None
            exhausted = db.scalar(
                select(Job.id).where(
                    Job.id == job_id,
                    or_(Job.state == "queued", and_(Job.state == "processing", Job.lease_until < now)),
                    Job.attempt_count >= 3,
                )
            )
            if current_job and exhausted:
                deleted = not owner or owner.deleted_at is not None or not current_item or current_item.status == "deleted"
                current_job.state = "deleted" if deleted else "failed"
                current_job.error_code = None if deleted else "retry_limit_exceeded"
                current_job.lease_until = None
                if current_item and not deleted:
                    current_item.status = "failed"
                _release_slot(db, current_job.owner_id, current_job.id)
                db.commit()
            return
        db.commit()

    with SessionLocal() as db:
        user = db.scalar(
            select(User).where(User.id == owner_id).with_for_update().execution_options(populate_existing=True)
        ) if owner_id else None
        job = db.scalar(
            select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
        )
        item = db.scalar(
            select(Item).where(Item.id == job.item_id).with_for_update().execution_options(populate_existing=True)
        ) if job else None
        if not job or not item or not user or user.deleted_at is not None or item.status == "deleted":
            if job:
                enqueue_object_cleanup(db, [job.staging_object_key], owner_id)
                job.state = "deleted"
                job.lease_until = None
                job.staging_object_key = ""
                job.staging_wrapped_dek = b""
            _release_slot(db, owner_id, job_id)
            db.commit()
            return
        item.status = "processing"
        db.commit()
        try:
            metadata = open_metadata(item.metadata_envelope, settings.kek_v1, metadata_aad(item.owner_id, item.id))
            plaintext = _read_staging(job, item, settings, store)
            if item.kind == "file":
                checked = validate_file(
                    metadata["original_filename"], metadata["content_type"], plaintext, settings.max_upload_bytes
                )
                if checked.size != item.original_size or hashlib.sha256(plaintext).hexdigest() != metadata["sha256"]:
                    raise InvalidUpload("payload_integrity_mismatch")
            variants: list[CipherVariant] = []
            created_objects: list[str] = []
            for algorithm in ALGORITHMS:
                result = crypto.make_variant(algorithm, plaintext)
                bundle = pack_inner_material(result["key"], result["iv"], result["ciphertext"])
                mode = MODE_BY_ALGORITHM[algorithm]
                crypto_version = "securebox-crypto-v1"
                aad = variant_aad(item.owner_id, item.id, algorithm, mode, crypto_version)
                envelope, wrapped = seal_payload(bundle, settings.kek_v1, aad)
                object_key = str(uuid.uuid4())
                store.put(object_key, envelope)
                created_objects.append(object_key)
                variants.append(
                    CipherVariant(
                        item_id=item.id,
                        algorithm=algorithm,
                        mode=mode,
                        backend=result["backend"],
                        crypto_version=crypto_version,
                        object_key=object_key,
                        wrapped_dek=wrapped,
                        byte_count=len(result["ciphertext"]),
                        digest_sha256=hashlib.sha256(result["ciphertext"]).hexdigest(),
                        encrypt_ms=result["encrypt_ns"] / 1_000_000,
                    )
                )
            with SessionLocal() as finish:
                owner = finish.scalar(
                    select(User)
                    .where(User.id == item.owner_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                current = finish.scalar(
                    select(Item)
                    .where(Item.id == item.id, Item.owner_id == item.owner_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                current_job = finish.scalar(
                    select(Job).where(Job.id == job.id).with_for_update().execution_options(populate_existing=True)
                )
                if (
                    not owner
                    or owner.deleted_at is not None
                    or not current
                    or current.status == "deleted"
                    or not current_job
                    or current_job.state != "processing"
                ):
                    enqueue_object_cleanup(finish, created_objects + [job.staging_object_key], item.owner_id)
                    if current_job:
                        current_job.state = "deleted"
                        current_job.lease_until = None
                        current_job.staging_object_key = ""
                        current_job.staging_wrapped_dek = b""
                    _release_slot(finish, item.owner_id, job.id)
                    finish.commit()
                    return
                finish.add_all(variants)
                current.status = "complete"
                current_job.state = "complete"
                current_job.lease_until = None
                current_job.error_code = None
                enqueue_object_cleanup(finish, [job.staging_object_key], item.owner_id)
                current_job.staging_object_key = ""
                current_job.staging_wrapped_dek = b""
                _release_slot(finish, current.owner_id, current_job.id)
                finish.commit()
        except Exception as exc:
            native_fault = isinstance(exc, NativeCryptoFault)
            error_code = "native_backend_failed" if native_fault else (exc.code if isinstance(exc, InvalidUpload) else "processing_failed")
            with SessionLocal() as failed:
                owner = failed.scalar(
                    select(User)
                    .where(User.id == item.owner_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                ) if item else None
                current_job = failed.scalar(
                    select(Job).where(Job.id == job_id).with_for_update().execution_options(populate_existing=True)
                )
                current_item = failed.scalar(
                    select(Item).where(Item.id == item.id).with_for_update().execution_options(populate_existing=True)
                ) if item else None
                enqueue_object_cleanup(
                    failed,
                    list(locals().get("created_objects", [])) + [job.staging_object_key],
                    owner_id,
                )
                if current_job and current_job.state == "processing":
                    deleted = not owner or owner.deleted_at is not None or not current_item or current_item.status == "deleted"
                    current_job.state = "deleted" if deleted else "failed"
                    current_job.error_code = None if deleted else error_code
                    current_job.lease_until = None
                    current_job.staging_object_key = ""
                    current_job.staging_wrapped_dek = b""
                    _release_slot(failed, current_job.owner_id, current_job.id)
                    if current_item and not deleted:
                        current_item.status = "failed"
                if current_job is None:
                    _release_slot(failed, owner_id, job_id)
                failed.commit()
            logger.error("upload_job_failed job_id=%s error_code=%s error_type=%s", job_id, error_code, type(exc).__name__)
