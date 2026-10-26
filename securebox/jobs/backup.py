from __future__ import annotations

import gzip
import io
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..config import get_settings

logger = logging.getLogger(__name__)


def _parse_db_url(database_url: str) -> dict:
    """Extract connection components from a postgresql+psycopg:// URL."""
    parsed = urlsplit(database_url)
    return {
        "host": parsed.hostname or "localhost",
        "port": str(parsed.port or 5432),
        "dbname": parsed.path.lstrip("/"),
        "user": parsed.username or "",
        "password": parsed.password or "",
    }


def _dump_database(conn: dict) -> bytes:
    """Run pg_dump and return the gzip-compressed dump as bytes."""
    env = os.environ.copy()
    env["PGPASSWORD"] = conn["password"]
    # --no-password prevents interactive prompts in automated contexts.
    cmd = [
        "pg_dump",
        "--no-password",
        "--format=plain",
        "--compress=0",
        f"--host={conn['host']}",
        f"--port={conn['port']}",
        f"--username={conn['user']}",
        conn["dbname"],
    ]
    result = subprocess.run(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=300,
    )
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        gz.write(result.stdout)
    return buf.getvalue()


def _s3_client(settings):
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        region_name=settings.s3_region or "auto",
    )


def _upload_backup(s3, bucket: str, key: str, data: bytes) -> None:
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType="application/gzip",
        ServerSideEncryption="AES256",
    )
    logger.info("backup_uploaded bucket=%s key=%s bytes=%d", bucket, key, len(data))


def _prune_old_backups(s3, bucket: str, prefix: str, retention_days: int) -> int:
    """Delete backup objects older than ``retention_days``. Returns count removed."""
    now = datetime.now(timezone.utc)
    paginator = s3.get_paginator("list_objects_v2")
    removed = 0
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            age_days = (now - obj["LastModified"]).days
            if age_days > retention_days:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
                logger.info("backup_pruned key=%s age_days=%d", obj["Key"], age_days)
                removed += 1
    return removed


def run_backup() -> None:
    """Full backup lifecycle: dump → upload → prune."""
    settings = get_settings()
    if not settings.s3_bucket:
        logger.error("backup_skipped reason=no_s3_bucket_configured")
        sys.exit(1)

    conn = _parse_db_url(settings.database_url)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    backup_key = f"backups/{timestamp}.sql.gz"
    prefix = "backups/"

    logger.info("backup_started key=%s", backup_key)
    try:
        dump_bytes = _dump_database(conn)
    except subprocess.CalledProcessError as exc:
        logger.error("backup_dump_failed stderr=%s", exc.stderr.decode(errors="replace"))
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logger.error("backup_dump_timeout")
        sys.exit(1)

    s3 = _s3_client(settings)
    try:
        _upload_backup(s3, settings.s3_bucket, backup_key, dump_bytes)
        pruned = _prune_old_backups(s3, settings.s3_bucket, prefix, settings.backup_retention_days)
        logger.info("backup_complete pruned=%d", pruned)
    except (BotoCoreError, ClientError) as exc:
        logger.error("backup_s3_error error=%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run_backup()
