from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import Settings, get_settings
from ...database import get_db
from ..errors import error_message

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/api/v1/config")
def public_config(settings: Settings = Depends(get_settings)):
    return {
        "registration_mode": settings.registration_mode,
        "max_file_bytes": {"jpg": 5 * 1024 * 1024, "jpeg": 5 * 1024 * 1024, "png": 5 * 1024 * 1024, "pdf": 10 * 1024 * 1024, "docx": 10 * 1024 * 1024, "xlsx": 10 * 1024 * 1024, "mp4": 20 * 1024 * 1024},
        "max_profile_bytes": 64 * 1024,
        "synthetic_data_only": settings.app_env != "development",
        "algorithms": ["aes", "des", "rc4"],
    }


@router.get("/api/v1/privacy")
def privacy_notice(settings: Settings = Depends(get_settings)):
    return {
        "controller": settings.controller_name,
        "contact": settings.privacy_contact,
        "purpose": "Educational storage and comparison of encryption algorithms for the SecureBox assignment.",
        "lawful_basis": "For a public deployment, the controller must document and publish the applicable lawful basis before collecting personal data. The local assignment demo should use synthetic data.",
        "data_categories": ["account username and password verifier", "optional profile fields", "uploaded files", "session metadata", "minimal security and benchmark metadata"],
        "retention_days": settings.item_ttl_days,
        "backup_retention_days": settings.backup_retention_days,
        "rights": ["request access or correction", "request deletion", "withdraw consent where consent is the applicable basis", "contact the controller about a privacy request"],
        "processing_note": "Files are validated and encrypted into comparison variants. RC4 and DES are obsolete educational algorithms; an AES-256-GCM envelope protects stored variants. This application is not a compliance certification.",
    }


@router.get("/api/v1/health")
def health(request: Request, db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
    except Exception as exc:
        logger.error("database_health_probe_failed request_id=%s error_type=%s", getattr(request.state, "request_id", ""), type(exc).__name__)
        return _unavailable(request)
    crypto = request.app.state.crypto.status()
    storage = getattr(request.app.state, "storage_health", "unknown")
    heartbeat = getattr(request.app.state, "worker_heartbeat", None)
    worker = "ok" if heartbeat is not None and time.monotonic() - heartbeat < 300 else "unavailable"
    ready = storage == "ok" and worker == "ok"
    payload = {
        "status": "ok" if ready else "unavailable",
        "crypto_backend": crypto.backend,
        "assembly_ready": crypto.asm_ready,
        "assembly_status": crypto.reason,
        "object_storage": storage,
        "worker": worker,
    }
    return JSONResponse(status_code=200 if ready else 503, content=payload)


def _unavailable(request: Request) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    return JSONResponse(status_code=503, content={
        "status": "unavailable",
        "error": {"code": "service_unavailable", "message": error_message("service_unavailable"), "request_id": request_id},
    })


@router.get("/")
def index():
    return FileResponse(Path(__file__).resolve().parents[2] / "static" / "index.html")
