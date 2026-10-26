"""Background processing and maintenance jobs.

The package re-exports the original ``securebox.jobs`` API for existing callers.
"""

from .benchmark import _load_plaintext, process_benchmark
from .common import ALGORITHMS, MODE_BY_ALGORITHM, _release_slot
from .maintenance import (
    cleanup_deleted_accounts,
    cleanup_ephemeral_records,
    cleanup_tombstones,
    expire_old_items,
)
from .processing import _read_staging, process_job
from .worker import run_worker_once

__all__ = [
    "ALGORITHMS",
    "MODE_BY_ALGORITHM",
    "cleanup_deleted_accounts",
    "cleanup_ephemeral_records",
    "cleanup_tombstones",
    "expire_old_items",
    "process_benchmark",
    "process_job",
    "run_worker_once",
]
