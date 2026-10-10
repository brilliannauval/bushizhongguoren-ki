from __future__ import annotations

import json
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...database import get_db
from ...models import BenchmarkRun, Job, User, UserWorkSlot, now_utc
from ...security import Principal
from ..dependencies import _csrf, _network, _principal, _rate
from ..errors import ApiError, _deny, error_message
from ...services.items import _owned_item

router = APIRouter(prefix="/api/v1")

@router.get("/jobs/{job_id}")
def get_job(job_id: str, principal: Principal = Depends(_principal), db: Session = Depends(get_db)):
    job = db.scalar(select(Job).where(Job.id == job_id, Job.owner_id == principal.user_id))
    if not job:
        _deny(404, "not_found")
    error_code = job.error_code if job.state == "failed" else None
    return {
        "id": job.id,
        "item_id": job.item_id,
        "status": job.state,
        "error_code": error_code,
        "error_message": error_message(error_code) if error_code else None,
    }


@router.post("/items/{item_id}/benchmarks", status_code=202)
def create_benchmark(item_id: str, request: Request, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"), db: Session = Depends(get_db), settings: Settings = Depends(get_settings), principal: Principal = Depends(_principal)):
    _csrf(request, db, settings, principal, csrf_token)
    _rate(db, settings, _network(request), "benchmark-network", 10, 3600)
    _rate(db, settings, "user:" + principal.user_id, "benchmark", 3, 3600)
    user = db.scalar(
        select(User)
        .where(User.id == principal.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not user or user.deleted_at is not None:
        _deny(401, "unauthenticated")
    item = _owned_item(db, principal, item_id)
    if item.status != "complete":
        _deny(409, "invalid_state")
    if db.get(UserWorkSlot, principal.user_id):
        _deny(409, "active_job_exists")
    cutoff = now_utc() - timedelta(hours=1)
    count = db.scalar(select(func.count(BenchmarkRun.id)).where(BenchmarkRun.owner_id == principal.user_id, BenchmarkRun.created_at >= cutoff)) or 0
    if count >= 3:
        _deny(429, "rate_limited")
    run_id = str(uuid.uuid4())
    run = BenchmarkRun(id=run_id, owner_id=principal.user_id, item_id=item.id, state="queued", warmups=1, sample_count=5)
    try:
        db.add_all((run, UserWorkSlot(owner_id=principal.user_id, work_id=run_id, work_type="benchmark")))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ApiError(409, "active_job_exists") from exc
    return {"run_id": run.id, "status": run.state}


@router.get("/benchmark-runs/{run_id}")
def get_benchmark(run_id: str, principal: Principal = Depends(_principal), db: Session = Depends(get_db)):
    run = db.scalar(select(BenchmarkRun).where(BenchmarkRun.id == run_id, BenchmarkRun.owner_id == principal.user_id))
    if not run:
        _deny(404, "not_found")
    error_code = run.error_code if run.state == "failed" else None
    return {
        "id": run.id,
        "item_id": run.item_id,
        "status": run.state,
        "results": json.loads(run.result_json) if run.state == "complete" and run.result_json else None,
        "error_code": error_code,
        "error_message": error_message(error_code) if error_code else None,
    }
