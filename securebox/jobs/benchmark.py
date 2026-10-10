from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta

from sqlalchemy import and_, or_, select, update

from ..config import Settings
from ..crypto import CryptoProvider
from ..database import SessionLocal
from ..envelope import metadata_aad, open_metadata, open_payload, unpack_inner_material, variant_aad
from ..models import BenchmarkRun, CipherVariant, Item, User, now_utc
from ..storage import PrivateObjectStore
from .common import ALGORITHMS, _release_slot

logger = logging.getLogger(__name__)


def _load_plaintext(item: Item, settings: Settings, store: PrivateObjectStore) -> bytes:
    with SessionLocal() as db:
        variants = {variant.algorithm: variant for variant in db.scalars(select(CipherVariant).where(CipherVariant.item_id == item.id)).all()}
        aes_variant = variants.get("aes")
        if not aes_variant or len(variants) != 3:
            raise ValueError("Variant set is incomplete")
        sealed = store.get(aes_variant.object_key)
        inner = open_payload(
            sealed,
            aes_variant.wrapped_dek,
            settings.kek_v1,
            variant_aad(item.owner_id, item.id, aes_variant.algorithm, aes_variant.mode, aes_variant.crypto_version),
        )
        key, iv, ciphertext = unpack_inner_material(inner)
        from ..crypto import CryptoProvider as Provider

        plaintext, _ = Provider().decrypt("aes", ciphertext, key, iv, "pycryptodome")
        metadata = open_metadata(item.metadata_envelope, settings.kek_v1, metadata_aad(item.owner_id, item.id))
        if hashlib.sha256(plaintext).hexdigest() != metadata["sha256"]:
            raise ValueError("Plaintext integrity mismatch")
        return plaintext

def process_benchmark(run_id: str, settings: Settings, store: PrivateObjectStore, crypto: CryptoProvider) -> None:
    owner_id = None
    item_id = None
    with SessionLocal() as db:
        run = db.get(BenchmarkRun, run_id)
        if not run:
            return
        owner_id = run.owner_id
        now = now_utc()
        claim = update(BenchmarkRun).where(
            BenchmarkRun.id == run_id,
            or_(BenchmarkRun.state == "queued", and_(BenchmarkRun.state == "processing", BenchmarkRun.lease_until < now)),
            BenchmarkRun.attempt_count < 2,
        ).values(state="processing", attempt_count=BenchmarkRun.attempt_count + 1, lease_until=now + timedelta(minutes=10))
        if db.execute(claim).rowcount != 1:
            db.rollback()
            owner = db.scalar(
                select(User).where(User.id == owner_id).with_for_update().execution_options(populate_existing=True)
            )
            current_run = db.scalar(
                select(BenchmarkRun).where(BenchmarkRun.id == run_id).with_for_update().execution_options(populate_existing=True)
            )
            current_item = db.scalar(
                select(Item)
                .where(Item.id == current_run.item_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ) if current_run else None
            exhausted = db.scalar(
                select(BenchmarkRun.id).where(
                    BenchmarkRun.id == run_id,
                    or_(
                        BenchmarkRun.state == "queued",
                        and_(BenchmarkRun.state == "processing", BenchmarkRun.lease_until < now),
                    ),
                    BenchmarkRun.attempt_count >= 2,
                )
            )
            if current_run and exhausted:
                deleted = (
                    not owner
                    or owner.deleted_at is not None
                    or not current_item
                    or current_item.status == "deleted"
                )
                current_run.state = "deleted" if deleted else "failed"
                current_run.error_code = None if deleted else "retry_limit_exceeded"
                current_run.lease_until = None
                if deleted:
                    current_run.result_json = None
                _release_slot(db, current_run.owner_id, current_run.id)
                db.commit()
            return
        db.commit()

    try:
        with SessionLocal() as db:
            owner = db.scalar(
                select(User).where(User.id == owner_id).with_for_update().execution_options(populate_existing=True)
            ) if owner_id else None
            run = db.scalar(
                select(BenchmarkRun)
                .where(BenchmarkRun.id == run_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            item = db.scalar(
                select(Item).where(
                    Item.id == run.item_id,
                    Item.owner_id == run.owner_id,
                    Item.status == "complete",
                ).with_for_update().execution_options(populate_existing=True)
            ) if run else None
            if not run or not owner or owner.deleted_at is not None or not item:
                if run:
                    run.state = "deleted"
                    run.error_code = None
                    run.lease_until = None
                    run.result_json = None
                _release_slot(db, owner_id, run_id)
                db.commit()
                return
            if run.state != "processing":
                _release_slot(db, owner_id, run_id)
                db.commit()
                return
            item_id = run.item_id
            db.commit()
        if not item:
            raise ValueError("Item unavailable")
        owner_id = item.owner_id
        plaintext = _load_plaintext(item, settings, store)
        results = {algorithm: crypto.benchmark(algorithm, plaintext, samples=5) for algorithm in ALGORITHMS}
        results["analysis"] = (
            "AES-128-CBC uses a 128-bit key but CBC does not authenticate the ciphertext. "
            "DES has only 56 effective key bits and is obsolete. RC4 is obsolete and has known biases. "
            "The AES-256-GCM storage envelope provides the at-rest integrity boundary. "
            "Timing reflects this backend, input size, host, and load; it does not establish a universal winner."
        )
        with SessionLocal() as db:
            owner = db.scalar(
                select(User).where(User.id == owner_id).with_for_update().execution_options(populate_existing=True)
            )
            run = db.scalar(
                select(BenchmarkRun)
                .where(BenchmarkRun.id == run_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            item = db.scalar(
                select(Item.id).where(
                    Item.id == item_id,
                    Item.owner_id == owner_id,
                    Item.status == "complete",
                ).with_for_update().execution_options(populate_existing=True)
            ) if item_id else None
            if not owner or owner.deleted_at is not None or not item:
                if run:
                    run.state = "deleted"
                    run.error_code = None
                    run.lease_until = None
                    run.result_json = None
                _release_slot(db, owner_id, run_id)
                db.commit()
                return
            if not run or run.state != "processing":
                _release_slot(db, owner_id, run_id)
                db.commit()
                return
            run.result_json = json.dumps(results, separators=(",", ":"))
            run.state = "complete"
            run.lease_until = None
            run.error_code = None
            _release_slot(db, run.owner_id, run.id)
            db.commit()
    except Exception as exc:
        with SessionLocal() as db:
            owner = db.scalar(
                select(User).where(User.id == owner_id).with_for_update().execution_options(populate_existing=True)
            ) if owner_id else None
            run = db.scalar(
                select(BenchmarkRun).where(BenchmarkRun.id == run_id).with_for_update().execution_options(populate_existing=True)
            )
            if run:
                item = db.scalar(
                    select(Item.id).where(
                        Item.id == item_id,
                        Item.owner_id == owner_id,
                        Item.status == "complete",
                    ).with_for_update()
                ) if item_id and owner_id else None
                if run.state == "processing":
                    deleted = not owner or owner.deleted_at is not None or not item
                    run.state = "deleted" if deleted else "failed"
                    run.error_code = None if deleted else "benchmark_failed"
                    run.lease_until = None
                    if deleted:
                        run.result_json = None
                    _release_slot(db, run.owner_id, run.id)
                db.commit()
            elif owner_id:
                _release_slot(db, owner_id, run_id)
                db.commit()
        logger.error("benchmark_failed run_id=%s error_type=%s", run_id, type(exc).__name__)
