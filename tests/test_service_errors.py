from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

from starlette.requests import Request

from securebox.api.errors import domain_error_handler
from securebox.domain.errors import DomainError
from securebox.security import Principal
from securebox.services.items import _owned_item


class _MissingItemDatabase:
    def scalar(self, _query):
        return None


def test_service_errors_are_domain_errors_without_api_imports():
    service_path = Path(__file__).parents[1] / "securebox" / "services" / "items.py"
    module = ast.parse(service_path.read_text())
    imported_modules = {
        node.module
        for node in ast.walk(module)
        if isinstance(node, ast.ImportFrom)
    }

    assert "..api.errors" not in imported_modules
    try:
        _owned_item(_MissingItemDatabase(), Principal("owner-id", "owner"), "item-id")
    except DomainError as exc:
        assert exc.code == "not_found"
    else:
        raise AssertionError("Missing owned items should raise a domain error")


def test_api_translates_domain_errors_to_safe_http_errors():
    request = Request({"type": "http", "headers": [], "state": {"request_id": "request-123"}})

    response = asyncio.run(domain_error_handler(request, DomainError("not_found")))
    payload = json.loads(response.body)
    assert response.status_code == 404
    assert payload["error"]["code"] == "not_found"
    assert "deleted" in payload["error"]["message"]
    assert payload["error"]["request_id"] == "request-123"

    unknown = asyncio.run(domain_error_handler(request, DomainError("internal_secret")))
    safe_payload = json.loads(unknown.body)
    assert unknown.status_code == 500
    assert safe_payload["error"]["code"] == "internal_error"
    assert "internal_secret" not in unknown.body.decode()


def test_securebox_jobs_package_keeps_existing_import_surface():
    from securebox.jobs import (
        ALGORITHMS,
        cleanup_tombstones,
        expire_old_items,
        process_benchmark,
        process_job,
        run_worker_once,
    )

    assert ALGORITHMS == ("aes", "des", "rc4")
    assert all(callable(function) for function in (
        cleanup_tombstones,
        expire_old_items,
        process_benchmark,
        process_job,
        run_worker_once,
    ))
