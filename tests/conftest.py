from __future__ import annotations

import base64
import os
import shutil
import tempfile
from pathlib import Path

# Each pytest process gets a private database/object directory so parallel runs
# cannot unlink one another's SQLite database during fixture setup.
TEST_ROOT = Path(tempfile.mkdtemp(prefix=f"securebox-test-{os.getpid()}-"))
os.environ["APP_ENV"] = "development"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_ROOT / 'securebox.db'}"
os.environ["OBJECT_DIR"] = str(TEST_ROOT / "objects")
os.environ["REGISTRATION_MODE"] = "open"
os.environ["KEK_V1"] = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
os.environ["RATE_LIMIT_PEPPER_V1"] = base64.urlsafe_b64encode(b"p" * 32).decode().rstrip("=")
os.environ["ITEM_TTL_DAYS"] = "30"
os.environ["BACKUP_RETENTION_DAYS"] = "30"

from fastapi.testclient import TestClient
import pytest

from securebox.main import app


@pytest.fixture
def client():
    from securebox.database import Base, engine

    # Isolate rate counters, accounts and background-job state between tests.
    with engine.begin() as connection:
        Base.metadata.drop_all(connection)
        Base.metadata.create_all(connection)
    object_dir = TEST_ROOT / "objects"
    shutil.rmtree(object_dir, ignore_errors=True)
    with TestClient(app) as test_client:
        yield test_client


def new_account(client: TestClient, name: str | None = None):
    import uuid

    username = name or "u" + uuid.uuid4().hex[:10]
    password = "correct horse battery staple"
    created = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert created.status_code == 201, created.text
    logged = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert logged.status_code == 200, logged.text
    headers = {"Origin": "http://testserver", "X-CSRF-Token": logged.json()["csrf_token"]}
    return username, password, headers


def png_bytes(color: tuple[int, int, int] = (10, 20, 30)) -> bytes:
    from io import BytesIO
    from PIL import Image

    stream = BytesIO()
    Image.new("RGB", (2, 2), color).save(stream, format="PNG")
    return stream.getvalue()
