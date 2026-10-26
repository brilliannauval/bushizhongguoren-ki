from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import delete, func, or_, select

from ..config import Settings
from ..database import SessionLocal
from ..models import BenchmarkRun, Item, Job, ObjectCleanup, RateCounter, SessionRecord, User, UserWorkSlot, now_utc
from ..storage import PrivateObjectStore
from .common import _release_slot, enqueue_object_cleanup

logger = logging.getLogger(__name__)


def _has_active_work(db, owner_id: str, item_id: str | None = None) -> bool:
    jobs = select(Job.id).where(Job.owner_id == owner_id, Job.state == "processing")
    benchmarks = select(BenchmarkRun.id).where(BenchmarkRun.owner_id == owner_id, BenchmarkRun.state == "processing")
    if item_id:
        benchmarks = benchmarks.where(BenchmarkRun.item_id == item_id)
    return bool(db.scalar(jobs.limit(1)) or db.scalar(benchmarks.limit(1)))


def cleanup_pending_objects(store: PrivateObjectStore, batch_size: int = 100) -> int:
    """Delete queued objects and retain failed/deferred rows for a later retry."""
    with SessionLocal() as db:
        pending = db.scalars(
            select(ObjectCleanup).order_by(ObjectCleanup.created_at).limit(batch_size)
        ).all()
        rows = [(row.object_key, row.owner_id) for row in pending]

    for object_key, owner_id in rows:
        if owner_id:
            with SessionLocal() as db:
                if _has_active_work(db, owner_id):
                    continue
        try:
            store.delete(object_key)
        except Exception as exc:
            logger.warning("object_cleanup_failed owner_id=%s error_type=%s", owner_id or "unknown", type(exc).__name__)
            continue
        with SessionLocal() as db:
            db.execute(delete(ObjectCleanup).where(ObjectCleanup.object_key == object_key))
            db.commit()

    with SessionLocal() as db:
        return int(db.scalar(select(func.count()).select_from(ObjectCleanup)) or 0)


def cleanup_tombstones(store: PrivateObjectStore) -> int:
    with SessionLocal() as db:
        items = db.scalars(select(Item).where(Item.status == "deleted")).all()
        for item in items:
            keys = [variant.object_key for variant in item.variants]
            if item.job and item.job.staging_object_key:
                keys.append(item.job.staging_object_key)
            enqueue_object_cleanup(db, keys, item.owner_id)
        db.commit()

    pending = cleanup_pending_objects(store)
    with SessionLocal() as db:
        items = db.scalars(select(Item).where(Item.status == "deleted")).all()
        for item in items:
            if _has_active_work(db, item.owner_id, item.id):
                continue
            if item.job:
                _release_slot(db, item.owner_id, item.job.id)
            runs = db.scalars(select(BenchmarkRun).where(BenchmarkRun.item_id == item.id)).all()
            for run in runs:
                _release_slot(db, run.owner_id, run.id)
                db.delete(run)
            db.delete(item)
        db.commit()
    cleanup_deleted_accounts()
    return pending


def cleanup_deleted_accounts() -> None:
    with SessionLocal() as db:
        candidates = db.scalars(select(User).where(User.deleted_at.is_not(None))).all()
        for user in candidates:
            has_items = db.scalar(select(Item.id).where(Item.owner_id == user.id).limit(1))
            has_cleanup = db.scalar(select(ObjectCleanup.object_key).where(ObjectCleanup.owner_id == user.id).limit(1))
            has_work = db.scalar(select(UserWorkSlot.owner_id).where(UserWorkSlot.owner_id == user.id).limit(1))
            if not has_items and not has_cleanup and not has_work:
                db.delete(user)
        db.commit()


def cleanup_ephemeral_records() -> None:
    """Prune shared rate buckets and sessions after their longest useful window."""
    now = now_utc()
    rate_cutoff = int(now.timestamp()) - 2 * 60 * 60
    idle_cutoff = now - timedelta(hours=1)
    with SessionLocal() as db:
        db.execute(delete(RateCounter).where(RateCounter.window_start < rate_cutoff))
        db.execute(delete(SessionRecord).where(or_(SessionRecord.expires_at <= now, SessionRecord.last_seen_at <= idle_cutoff)))
        db.commit()


def expire_old_items(settings: Settings, store: PrivateObjectStore) -> None:
    cutoff = now_utc() - timedelta(days=settings.item_ttl_days)
    with SessionLocal() as db:
        items = db.scalars(select(Item).where(Item.status != "deleted", Item.created_at < cutoff)).all()
        for item in items:
            db.scalar(select(User.id).where(User.id == item.owner_id).with_for_update())
            item.status = "deleted"
            if item.job and item.job.state != "processing":
                item.job.state = "deleted"
                item.job.lease_until = None
                _release_slot(db, item.owner_id, item.job.id)
            for run in db.scalars(select(BenchmarkRun).where(BenchmarkRun.item_id == item.id)).all():
                if run.state != "processing":
                    run.state = "deleted"
                    run.lease_until = None
                    run.result_json = None
                    _release_slot(db, run.owner_id, run.id)
        db.commit()
    cleanup_tombstones(store)
    cleanup_deleted_accounts()
