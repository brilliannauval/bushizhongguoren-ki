from __future__ import annotations

import gzip
import logging
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlsplit

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..config import get_settings

logger = logging.getLogger(__name__)


def _redact(value: str) -> str:
    """Replace all but the first 4 chars of a string with asterisks."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * (len(value) - 4)


def _parse_db_url(database_url: str) -> tuple[dict, dict]:
    """Return (conn_params, ssl_env) derived from *database_url*.

    ``ssl_env`` contains the libpq variables that preserve the TLS settings
    used by SQLAlchemy and Alembic.
    """
    parsed = urlsplit(database_url)
    qs = parse_qs(parsed.query)

    conn = {
        "host": parsed.hostname or "localhost",
        "port": str(parsed.port or 5432),
        "dbname": (parsed.path or "").lstrip("/"),
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
    }

    ssl_env: dict[str, str] = {}
    param_map = {
        "sslmode":     "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "sslcert":     "PGSSLCERT",
        "sslkey":      "PGSSLKEY",
    }
    for url_key, env_key in param_map.items():
        val = qs.get(url_key, [None])[0]
        if val:
            ssl_env[env_key] = val

    if (parsed.scheme == "postgres" or parsed.scheme.startswith("postgresql")) and "PGSSLMODE" not in ssl_env:
        raise ValueError("PostgreSQL DATABASE_URL must set sslmode")

    return conn, ssl_env


def _dump_to_file(conn: dict, ssl_env: dict, dest_path: str) -> None:
    """Stream pg_dump into a gzip file, with a bounded wall-clock time."""
    env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "PGPASSWORD": conn["password"]}
    env.update(ssl_env)

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

    with open(dest_path, "wb") as out_fh, gzip.open(out_fh, "wb", compresslevel=6) as gz_fh:
        with subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as proc:
            if proc.stdout is None:
                raise RuntimeError("pg_dump stdout pipe was not created")
            deadline = time.monotonic() + 300
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        proc.kill()
                        proc.wait()
                        raise subprocess.TimeoutExpired(cmd, 300)
                    ready = selector.select(min(remaining, 1))
                    if ready:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if chunk:
                            gz_fh.write(chunk)
                            continue
                        selector.unregister(proc.stdout)
                        break
                    if proc.poll() is not None:
                        break
            try:
                return_code = proc.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(cmd, 300) from exc
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, cmd)


def _s3_client(settings):
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        region_name=settings.s3_region or "auto",
    )


def _upload_file(s3, bucket: str, key: str, local_path: str) -> int:
    """Upload *local_path* to S3 using multipart for large files. Returns file size."""
    file_size = os.path.getsize(local_path)
    with open(local_path, "rb") as fh:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=fh,
            ContentType="application/gzip",
            ServerSideEncryption="AES256",
        )
    logger.info("backup_uploaded bucket=%s key=%s bytes=%d", bucket, key, file_size)
    return file_size


def _prune_old_backups(s3, bucket: str, prefix: str, retention_days: int) -> int:
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
    settings = get_settings()
    if not settings.s3_bucket:
        logger.error("backup_skipped reason=no_s3_bucket_configured")
        sys.exit(1)

    conn, ssl_env = _parse_db_url(settings.database_url)

    logger.info(
        "backup_started host=%s port=%s db=%s sslmode=%s",
        conn["host"], conn["port"], conn["dbname"],
        ssl_env.get("PGSSLMODE", "unset"),
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    backup_key = f"backups/{timestamp}.sql.gz"

    tmp_dir = tempfile.mkdtemp(prefix="securebox-backup-")
    tmp_path = os.path.join(tmp_dir, "dump.sql.gz")
    try:
        try:
            _dump_to_file(conn, ssl_env, tmp_path)
        except subprocess.CalledProcessError as exc:
            logger.error(
                "backup_dump_failed returncode=%d",
                exc.returncode,
            )
            sys.exit(1)
        except subprocess.TimeoutExpired:
            logger.error("backup_dump_timeout")
            sys.exit(1)

        s3 = _s3_client(settings)
        try:
            _upload_file(s3, settings.s3_bucket, backup_key, tmp_path)
            pruned = _prune_old_backups(
                s3, settings.s3_bucket, "backups/", settings.backup_retention_days
            )
            logger.info("backup_complete pruned=%d", pruned)
        except (BotoCoreError, ClientError) as exc:
            logger.error("backup_s3_error error_type=%s", type(exc).__name__)
            sys.exit(1)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run_backup()
