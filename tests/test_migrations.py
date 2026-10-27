from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def test_migrations_upgrade_to_head_repeatedly(tmp_path):
    root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "migration-test.db"
    environment = os.environ.copy()
    environment.update(
        APP_ENV="development",
        DATABASE_URL=f"sqlite:///{database_path}",
        OBJECT_DIR=str(tmp_path / "objects"),
    )
    for _ in range(2):
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0005_job_lease_tokens"
        for table in ("jobs", "benchmark_runs"):
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            assert "lease_token" in columns


def test_lease_token_migration_repairs_existing_revision_four_schema(tmp_path):
    root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "revision-four.db"
    environment = os.environ.copy()
    environment.update(
        APP_ENV="development",
        DATABASE_URL=f"sqlite:///{database_path}",
        OBJECT_DIR=str(tmp_path / "objects"),
    )
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "0004_object_cleanup"],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

    with sqlite3.connect(database_path) as connection:
        for table in ("jobs", "benchmark_runs"):
            connection.execute(f"ALTER TABLE {table} DROP COLUMN lease_token")
        connection.commit()

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(database_path) as connection:
        for table in ("jobs", "benchmark_runs"):
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            assert "lease_token" in columns
