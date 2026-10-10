from __future__ import annotations

from sqlalchemy import and_, or_, select

from ..config import Settings
from ..crypto import CryptoProvider
from ..database import SessionLocal
from ..models import BenchmarkRun, Job, now_utc
from ..storage import PrivateObjectStore
from .benchmark import process_benchmark
from .processing import process_job


def run_worker_once(settings: Settings, store: PrivateObjectStore, crypto: CryptoProvider) -> bool:
    with SessionLocal() as db:
        now = now_utc()
        job_id = db.scalar(
            select(Job.id)
            .where(or_(Job.state == "queued", and_(Job.state == "processing", Job.lease_until < now)))
            .order_by(Job.created_at)
            .limit(1)
        )
        benchmark_id = None
        if not job_id:
            benchmark_id = db.scalar(
                select(BenchmarkRun.id)
                .where(or_(BenchmarkRun.state == "queued", and_(BenchmarkRun.state == "processing", BenchmarkRun.lease_until < now)))
                .order_by(BenchmarkRun.created_at)
                .limit(1)
            )
    if job_id:
        process_job(job_id, settings, store, crypto)
        return True
    if benchmark_id:
        process_benchmark(benchmark_id, settings, store, crypto)
        return True
    return False
