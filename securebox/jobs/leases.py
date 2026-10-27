from __future__ import annotations

import logging
import threading
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import and_, or_, update

from ..database import SessionLocal
from ..models import now_utc

logger = logging.getLogger(__name__)


def claim_lease(db, model, work_id: str, *, max_attempts: int, lease_seconds: int) -> str | None:
    now = now_utc()
    token = str(uuid4())
    columns = model.c if hasattr(model, "c") else model
    result = db.execute(
        update(model)
        .where(
            columns.id == work_id,
            or_(
                columns.state == "queued",
                and_(
                    columns.state == "processing",
                    or_(columns.lease_until.is_(None), columns.lease_until < now),
                ),
            ),
            columns.attempt_count < max_attempts,
        )
        .values(
            state="processing",
            attempt_count=columns.attempt_count + 1,
            lease_until=now + timedelta(seconds=lease_seconds),
            lease_token=token,
        )
    )
    return token if result.rowcount == 1 else None


class LeaseHeartbeat:
    def __init__(self, model, work_id: str, token: str, lease_seconds: int, interval_seconds: int = 20):
        self.model = model
        self.work_id = work_id
        self.token = token
        self.lease_seconds = lease_seconds
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"lease-{work_id[:8]}", daemon=True)

    @property
    def owned(self) -> bool:
        return not self._lost.is_set()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()

    def _renew(self) -> bool:
        with SessionLocal() as db:
            result = db.execute(
                update(self.model)
                .where(
                    self.model.id == self.work_id,
                    self.model.state == "processing",
                    self.model.lease_token == self.token,
                )
                .values(lease_until=now_utc() + timedelta(seconds=self.lease_seconds))
            )
            db.commit()
            return result.rowcount == 1

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                if not self._renew():
                    self._lost.set()
                    logger.warning("job_lease_lost work_id=%s", self.work_id)
                    return
            except Exception as exc:
                logger.warning(
                    "job_lease_heartbeat_failed work_id=%s error_type=%s",
                    self.work_id,
                    type(exc).__name__,
                )
