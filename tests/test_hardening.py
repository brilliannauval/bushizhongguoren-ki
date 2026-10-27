from __future__ import annotations

import json
import os
import struct
import subprocess
from datetime import timezone
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import select, update

from securebox.database import SessionLocal
from securebox.jobs.backup import _dump_to_file, _parse_db_url
from securebox.jobs.leases import LeaseHeartbeat
from securebox.models import Job, now_utc
from securebox.validation import _validate_mp4


def test_backup_preserves_verified_libpq_tls_options_and_decodes_credentials():
    connection, ssl_env = _parse_db_url(
        "postgresql+psycopg://backup:p%40ss@db.example:5432/securebox"
        "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fdb-ca.pem"
    )
    assert connection["password"] == "p@ss"
    assert ssl_env == {
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": "/etc/ssl/db-ca.pem",
    }


def test_backup_failure_does_not_capture_or_return_raw_stderr(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_dump = fake_bin / "pg_dump"
    fake_dump.write_text("#!/bin/sh\necho \"$PGPASSWORD\" >&2\nexit 2\n", encoding="ascii")
    fake_dump.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.defpath}")
    destination = tmp_path / "backup.sql.gz"

    with pytest.raises(subprocess.CalledProcessError) as error:
        _dump_to_file(
            {"host": "db", "port": "5432", "dbname": "securebox", "user": "backup", "password": "do-not-log"},
            {"PGSSLMODE": "verify-full", "PGSSLROOTCERT": "/ca.pem"},
            str(destination),
        )

    assert error.value.stderr is None
    assert "do-not-log" not in repr(error.value)


def test_ffprobe_runs_with_minimal_environment_and_resource_limits(monkeypatch):
    monkeypatch.setattr("securebox.validation.shutil.which", lambda _name: "/usr/bin/ffprobe")
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"format": {"duration": "1.5"}, "streams": [{"codec_type": "video", "width": 640, "height": 480}]}
            ).encode(),
        )

    monkeypatch.setattr("securebox.validation.subprocess.run", fake_run)
    data = (
        struct.pack(">I4s4s", 12, b"ftyp", b"isom")
        + struct.pack(">I4s", 8, b"moov")
        + struct.pack(">I4s", 8, b"mdat")
    )
    _validate_mp4(data)

    assert captured["cwd"] == "/tmp"
    assert captured["env"] == {"PATH": os.defpath, "LANG": "C"}
    assert captured["timeout"] == 3
    assert captured["close_fds"] is True
    assert captured["preexec_fn"] is not None
    assert "pipe,crypto,data" in captured["command"]


def test_job_lease_heartbeat_renews_only_the_current_fencing_token(client):
    job_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    token = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(
            Job(
                id=job_id,
                item_id=str(uuid.uuid4()),
                owner_id=owner_id,
                state="processing",
                attempt_count=1,
                lease_until=now_utc(),
                lease_token=token,
                staging_object_key=str(uuid.uuid4()),
                staging_wrapped_dek=b"wrapped",
                idempotency_key=str(uuid.uuid4()),
            )
        )
        db.commit()

    heartbeat = LeaseHeartbeat(Job, job_id, token, lease_seconds=300, interval_seconds=3600)
    assert heartbeat._renew()
    with SessionLocal() as db:
        renewed = db.get(Job, job_id)
        assert renewed and renewed.lease_until is not None
        assert (renewed.lease_until.replace(tzinfo=timezone.utc) - now_utc()).total_seconds() > 200
        db.execute(update(Job).where(Job.id == job_id).values(lease_token=str(uuid.uuid4())))
        db.commit()
    assert not heartbeat._renew()
    heartbeat.stop()
