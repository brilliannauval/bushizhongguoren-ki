from __future__ import annotations

import logging
import signal
import sys
import time

from ..config import get_settings
from ..crypto import CryptoProvider
from ..database import init_db
from ..jobs import (
    cleanup_deleted_accounts,
    cleanup_ephemeral_records,
    cleanup_tombstones,
    expire_old_items,
    run_worker_once,
)
from ..storage import PrivateObjectStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

_running = True


def _handle_signal(signum, frame): 
    global _running
    logger.info("worker_shutdown signal=%d", signum)
    _running = False


def main() -> int:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    settings = get_settings()
    if settings.app_env == "development":
        init_db()

    store = PrivateObjectStore(settings)
    crypto = CryptoProvider()
    last_cleanup = 0.0

    logger.info("worker_started env=%s", settings.app_env)
    while _running:
        try:
            worked = run_worker_once(settings, store, crypto)
            now = time.monotonic()
            if now - last_cleanup > 60:
                cleanup_tombstones(store)
                cleanup_deleted_accounts()
                cleanup_ephemeral_records()
                expire_old_items(settings, store)
                last_cleanup = now
            if not worked:
                time.sleep(0.5)
        except Exception as exc:
            logger.error("worker_iteration_failed error_type=%s", type(exc).__name__)
            time.sleep(1)

    logger.info("worker_stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
