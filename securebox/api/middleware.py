from __future__ import annotations

import json
import uuid

from .errors import error_message

class BodyLimitMiddleware:
    """Enforce byte limits for declared and streamed bodies before multipart parsing."""

    def __init__(self, app, multipart_limit: int = 20 * 1024 * 1024 + 64 * 1024, json_limit: int = 128 * 1024):
        self.app, self.multipart_limit, self.json_limit = app, multipart_limit, json_limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_type = headers.get(b"content-type", b"").lower()
        limit = self.multipart_limit if content_type.startswith(b"multipart/form-data") else self.json_limit
        request_id = scope.get("state", {}).get("request_id", "")
        rejection_body = json.dumps({
            "error": {
                "code": "request_too_large",
                "message": error_message("request_too_large"),
                "request_id": request_id,
            }
        }, separators=(",", ":")).encode("utf-8")
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > limit:
                    await self._reject(send, rejection_body)
                    return
            except ValueError:
                await self._reject(send, rejection_body)
                return
        total, exceeded = 0, False
        rejection_started, rejection_finished = False, False

        async def limited_receive():
            nonlocal total, exceeded
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def limited_send(message):
            nonlocal rejection_started, rejection_finished
            if exceeded:
                if message["type"] == "http.response.start" and not rejection_started:
                    rejection_started = True
                    await send({
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(rejection_body)).encode()), (b"cache-control", b"no-store")],
                    })
                elif message["type"] == "http.response.body" and rejection_started and not rejection_finished:
                    rejection_finished = True
                    await send({"type": "http.response.body", "body": rejection_body, "more_body": False})
                return
            await send(message)

        try:
            await self.app(scope, limited_receive, limited_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded and not rejection_started:
            await self._reject(send, rejection_body)

    async def _reject(self, send, body: bytes):
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", [])) + [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"content-security-policy", b"default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' blob:; media-src 'self' blob:; script-src 'self'; style-src 'self'; connect-src 'self'"),
                    (b"cache-control", b"no-store"),
                    (b"x-request-id", request_id.encode("ascii")),
                ]
                if scope.get("scheme") == "https":
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message = dict(message, headers=headers)
            await send(message)

        await self.app(scope, receive, secure_send)
