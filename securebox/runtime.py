from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import get_settings
from .crypto import CryptoProvider
from .database import engine, init_db
from .jobs import (
    cleanup_deleted_accounts,
    cleanup_ephemeral_records,
    cleanup_tombstones,
    expire_old_items,
    run_worker_once,
)
from .storage import PrivateObjectStore

logger = logging.getLogger(__name__)

async def _worker_loop(app: FastAPI):
    last_cleanup = 0.0
    last_storage_probe = 0.0
    while True:
        try:
            app.state.worker_heartbeat = time.monotonic()
            worked = await asyncio.to_thread(run_worker_once, app.state.settings, app.state.store, app.state.crypto)
            current = asyncio.get_running_loop().time()
            if current - last_storage_probe > 60:
                try:
                    await asyncio.to_thread(app.state.store.check_health)
                    app.state.storage_health = "ok"
                except Exception as exc:
                    app.state.storage_health = "unavailable"
                    logger.warning("storage_health_probe_failed error_type=%s", type(exc).__name__)
                last_storage_probe = current
            if current - last_cleanup > 60:
                await asyncio.to_thread(cleanup_tombstones, app.state.store)
                await asyncio.to_thread(cleanup_deleted_accounts)
                await asyncio.to_thread(cleanup_ephemeral_records)
                await asyncio.to_thread(expire_old_items, app.state.settings, app.state.store)
                last_cleanup = current
            if not worked:
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("worker_iteration_failed error_type=%s", type(exc).__name__)
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(application: FastAPI):
    settings = get_settings()
    application.state.settings = settings
    application.state.store = PrivateObjectStore(settings)
    application.state.crypto = CryptoProvider()
    application.state.storage_health = "unknown"
    application.state.worker_heartbeat = None
    if settings.app_env == "development":
        init_db()
    else:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
    await asyncio.to_thread(cleanup_tombstones, application.state.store)
    await asyncio.to_thread(cleanup_ephemeral_records)
    task = asyncio.create_task(_worker_loop(application), name="securebox-worker")
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
