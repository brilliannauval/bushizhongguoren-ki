from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..domain.errors import DomainError
from ..error_messages import ERROR_MESSAGES, error_message, public_error_code

logger = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code


def _deny(status: int, code: str):
    raise ApiError(status, code)


_DOMAIN_ERROR_STATUS = {
    "active_job_exists": 409,
    "invalid_state": 409,
    "not_found": 404,
    "storage_quota_exceeded": 409,
}


async def domain_error_handler(request: Request, exc: DomainError):
    """Translate a domain error into the API's stable HTTP response."""
    code = public_error_code(exc.code)
    status = _DOMAIN_ERROR_STATUS.get(code)
    if status is None:
        status, code = 500, "internal_error"
    request_id = getattr(request.state, "request_id", "")
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": error_message(code), "request_id": request_id}})


async def api_error_handler(request: Request, exc: ApiError):
    request_id = getattr(request.state, "request_id", "")
    code = public_error_code(exc.code)
    return JSONResponse(status_code=exc.status, content={"error": {"code": code, "message": error_message(code), "request_id": request_id}})


async def http_error_handler(request: Request, exc: HTTPException):
    details = exc.detail if isinstance(exc.detail, dict) else {}
    code = details.get("code", {400: "invalid_request", 401: "unauthenticated", 403: "forbidden", 404: "not_found", 409: "conflict", 413: "request_too_large", 415: "unsupported_file_type", 422: "invalid_request", 429: "rate_limited", 500: "internal_error", 503: "service_unavailable"}.get(exc.status_code, "internal_error"))
    code = public_error_code(code)
    request_id = getattr(request.state, "request_id", "")
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": code, "message": error_message(code), "request_id": request_id}}, headers=exc.headers)


async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": {"code": "invalid_request", "message": error_message("invalid_request"), "request_id": getattr(request.state, "request_id", "")}})


async def unexpected_error_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled_request request_id=%s method=%s error_type=%s",
        getattr(request.state, "request_id", ""),
        request.method,
        type(exc).__name__,
    )
    return JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": error_message("internal_error"), "request_id": getattr(request.state, "request_id", "")}})


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(DomainError, domain_error_handler)
    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unexpected_error_handler)
