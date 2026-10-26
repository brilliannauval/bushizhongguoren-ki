from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from .config import Settings

_KEY_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{27}$")


class PrivateObjectStore:
    """Private local development storage or private S3-compatible object storage."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.remote = bool(settings.s3_bucket)
        self.client = None
        if self.remote:
            import boto3
            from botocore.config import Config

            self.client = boto3.client(
                "s3",
                endpoint_url=settings.s3_endpoint_url,
                aws_access_key_id=settings.s3_access_key_id,
                aws_secret_access_key=settings.s3_secret_access_key,
                region_name=settings.s3_region,
                config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 2}),
            )
        else:
            settings.object_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(settings.object_dir, 0o700)

    def check_health(self) -> None:
        """Perform a bounded storage probe for the background readiness cache."""
        if self.remote:
            self.client.head_bucket(Bucket=self.settings.s3_bucket)
            return
        if not self.settings.object_dir.is_dir() or not os.access(self.settings.object_dir, os.R_OK | os.W_OK):
            raise OSError("Local object storage is unavailable")

    @staticmethod
    def _check_key(key: str) -> None:
        if not _KEY_RE.fullmatch(key):
            raise ValueError("Invalid object key")

    def put(self, key: str, data: bytes) -> None:
        self._check_key(key)
        if self.remote:
            self.client.put_object(Bucket=self.settings.s3_bucket, Key=key, Body=data)
            return
        target = self.settings.object_dir / key
        fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=self.settings.object_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def get(self, key: str) -> bytes:
        self._check_key(key)
        if self.remote:
            response = self.client.get_object(Bucket=self.settings.s3_bucket, Key=key)
            with response["Body"] as body:
                return body.read()
        return (self.settings.object_dir / key).read_bytes()

    def delete(self, key: str) -> None:
        self._check_key(key)
        if self.remote:
            self.client.delete_object(Bucket=self.settings.s3_bucket, Key=key)
            return
        try:
            (self.settings.object_dir / key).unlink()
        except FileNotFoundError:
            pass
