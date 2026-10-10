from __future__ import annotations

import asyncio
import json
import threading
from io import BytesIO
from datetime import datetime, timedelta, timezone
import time
import uuid

from fastapi.testclient import TestClient
from PIL import Image


def _png() -> bytes:
    stream = BytesIO()
    Image.new("RGB", (3, 2), (20, 40, 60)).save(stream, format="PNG")
    return stream.getvalue()


def _register_and_login(client: TestClient, label: str = "user") -> tuple[str, str, dict[str, str]]:
    username = f"{label}-{uuid.uuid4().hex[:10]}"
    password = "correct horse battery staple"
    response = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    headers = {"Origin": "http://testserver", "X-CSRF-Token": response.json()["csrf_token"]}
    return username, password, headers


def _wait_for_job(client: TestClient, job_id: str, headers: dict[str, str], timeout: float = 20) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert response.status_code == 200, response.text
        result = response.json()
        if result["status"] in {"complete", "failed"}:
            return result
        time.sleep(0.5)
    raise AssertionError("The background job did not finish before the test timeout")


def _wait_for_benchmark(client: TestClient, run_id: str, headers: dict[str, str], timeout: float = 45) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/benchmark-runs/{run_id}", headers=headers)
        assert response.status_code == 200, response.text
        result = response.json()
        if result["status"] in {"complete", "failed"}:
            return result
        time.sleep(1.5)
    raise AssertionError("The benchmark did not finish before the test timeout")


def test_registration_login_and_errors_are_generic(client):
    username, password, _headers = _register_and_login(client)
    response = client.get("/api/v1/me")
    assert response.status_code == 200
    assert response.json() == {"username": username}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"

    invalid = client.post("/api/v1/auth/register", json={"username": "short", "password": "short", "unexpected": "x"})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_request"
    assert invalid.json()["error"]["message"] == "Some information is missing or doesn't look right. Review the fields and try again."
    assert "unexpected" not in invalid.text

    duplicate = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "registration_conflict"
    assert duplicate.json()["error"]["message"] == "We couldn't create an account with those details. Try a different username, or sign in if you may already have an account."
    assert username not in duplicate.text

    client.post("/api/v1/auth/logout", headers={"Origin": "http://testserver", "X-CSRF-Token": client.get("/api/v1/auth/session").json()["csrf_token"]})
    wrong_password = client.post("/api/v1/auth/login", json={"username": username, "password": "wrong password"})
    unknown_username = client.post("/api/v1/auth/login", json={"username": "not-a-real-user", "password": "wrong password"})
    assert wrong_password.status_code == 401
    assert wrong_password.json()["error"]["code"] == "invalid_credentials"
    assert wrong_password.json()["error"]["message"] == "The username or password is incorrect."
    assert unknown_username.status_code == 401
    assert unknown_username.json()["error"]["code"] == wrong_password.json()["error"]["code"]
    assert unknown_username.json()["error"]["message"] == wrong_password.json()["error"]["message"]


def test_cookie_mutations_require_csrf_and_same_origin(client):
    username, _password, headers = _register_and_login(client)
    body = {"display_name": "Synthetic User"}
    missing_token = client.put("/api/v1/me/profile", json=body, headers={"Origin": "http://testserver"})
    assert missing_token.status_code == 403
    assert missing_token.json()["error"]["code"] == "session_check_failed"
    assert "Reload the page" in missing_token.json()["error"]["message"]
    wrong_origin = client.put("/api/v1/me/profile", json=body, headers={**headers, "Origin": "https://attacker.invalid"})
    assert wrong_origin.status_code == 403
    assert wrong_origin.json()["error"]["code"] == "session_check_failed"
    # Local browser origins include the published port. The reverse proxy must
    # preserve it in Host for the same-origin CSRF check to accept this request.
    port_headers = {**headers, "Origin": "http://testserver:8080", "Host": "testserver:8080"}
    accepted = client.put("/api/v1/me/profile", json=body, headers=port_headers)
    assert accepted.status_code == 202, accepted.text
    assert accepted.json()["status"] == "queued"


def test_session_csrf_is_stable_migrates_legacy_digest_and_is_session_scoped(client):
    from sqlalchemy import select

    from securebox.database import SessionLocal
    from securebox.models import SessionRecord
    from securebox.security import _digest_session

    username, password, headers = _register_and_login(client)
    first_token = headers["X-CSRF-Token"]
    first_cookie = client.cookies.get("securebox_session")
    with SessionLocal() as db:
        record = db.scalar(select(SessionRecord).where(SessionRecord.token_digest == _digest_session(first_cookie)))
        record.csrf_digest = _digest_session("legacy-random-csrf-token")
        db.commit()

    migrated = client.get("/api/v1/auth/session")
    assert migrated.status_code == 200
    assert migrated.json()["csrf_token"] == first_token
    with SessionLocal() as db:
        record = db.scalar(select(SessionRecord).where(SessionRecord.token_digest == _digest_session(first_cookie)))
        migrated_digest = record.csrf_digest
        assert migrated_digest == _digest_session(first_token)
    assert client.get("/api/v1/auth/session").json()["csrf_token"] == first_token
    with SessionLocal() as db:
        record = db.scalar(select(SessionRecord).where(SessionRecord.token_digest == _digest_session(first_cookie)))
        assert record.csrf_digest == migrated_digest

    second_login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert second_login.status_code == 200
    second_token = second_login.json()["csrf_token"]
    second_cookie = client.cookies.get("securebox_session")
    assert second_token != first_token
    assert client.get("/api/v1/auth/session").json()["csrf_token"] == second_token

    client.cookies.set("securebox_session", second_cookie)
    cross_session = client.put(
        "/api/v1/me/profile",
        json={"display_name": "Session Isolation"},
        headers={"Origin": "http://testserver", "X-CSRF-Token": first_token},
    )
    assert cross_session.status_code == 403
    logged_out = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "http://testserver", "X-CSRF-Token": second_token},
    )
    assert logged_out.status_code == 204

    client.cookies.set("securebox_session", first_cookie)
    assert client.get("/api/v1/auth/session").json()["csrf_token"] == first_token
    accepted = client.put(
        "/api/v1/me/profile",
        json={"display_name": "Stable Tab Token"},
        headers={"Origin": "http://testserver", "X-CSRF-Token": first_token},
    )
    assert accepted.status_code == 202, accepted.text


def test_password_whitespace_is_preserved_and_birth_date_is_a_real_calendar_date(client):
    username = f"space-{uuid.uuid4().hex[:10]}"
    password = "  correct horse battery staple  "
    created = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert created.status_code == 201, created.text
    assert client.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"username": username, "password": password.strip()}).status_code == 401
    csrf = client.get("/api/v1/auth/session").json()["csrf_token"]
    invalid_date = client.put(
        "/api/v1/me/profile",
        json={"display_name": "Synthetic Date", "date_of_birth": "2025-02-30"},
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert invalid_date.status_code == 422


def test_account_deletion_revokes_all_sessions_and_retries_active_object_cleanup(client):
    from sqlalchemy import select

    from securebox.database import SessionLocal
    from securebox.jobs.common import enqueue_object_cleanup
    from securebox.jobs.maintenance import cleanup_tombstones
    from securebox.models import Item, Job, ObjectCleanup, User, UserWorkSlot, now_utc

    username, password, headers = _register_and_login(client, "deleteowner")
    first_cookie = client.cookies.get("securebox_session")
    first_token = headers["X-CSRF-Token"]
    second_login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert second_login.status_code == 200
    second_cookie = client.cookies.get("securebox_session")
    second_token = second_login.json()["csrf_token"]

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        owner_id = user.id
        item_id, job_id = str(uuid.uuid4()), str(uuid.uuid4())
        stage_key = str(uuid.uuid4())
        item = Item(
            id=item_id,
            owner_id=owner_id,
            kind="file",
            status="processing",
            original_size=32,
            metadata_envelope=b"encrypted-metadata-fixture",
        )
        job = Job(
            id=job_id,
            item_id=item_id,
            owner_id=owner_id,
            state="processing",
            attempt_count=1,
            lease_until=now_utc() + timedelta(minutes=5),
            staging_object_key=stage_key,
            staging_wrapped_dek=b"wrapped-fixture",
            idempotency_key=str(uuid.uuid4()),
        )
        db.add_all((item, job, UserWorkSlot(owner_id=owner_id, work_id=job_id, work_type="upload")))
        db.commit()
    store = client.app.state.store
    store.put(stage_key, b"synthetic encrypted stage")

    client.cookies.set("securebox_session", first_cookie)
    missing_token = client.delete("/api/v1/me", headers={"Origin": "http://testserver"})
    assert missing_token.status_code == 403
    wrong_origin = client.delete(
        "/api/v1/me",
        headers={"Origin": "https://attacker.invalid", "X-CSRF-Token": first_token},
    )
    assert wrong_origin.status_code == 403
    deleted = client.delete(
        "/api/v1/me",
        headers={"Origin": "http://testserver", "X-CSRF-Token": first_token},
    )
    assert deleted.status_code == 204
    assert "securebox_session" in deleted.headers.get("set-cookie", "")

    with SessionLocal() as db:
        user = db.get(User, owner_id)
        item = db.get(Item, item_id)
        job = db.get(Job, job_id)
        assert user and user.deleted_at is not None
        assert item and item.status == "deleted"
        assert job and job.state == "processing"
        assert db.get(ObjectCleanup, stage_key) is not None

    # In-flight work holds its cleanup rows until it has either committed or
    # handed any late object keys to the durable cleanup ledger.
    assert cleanup_tombstones(store) > 0
    assert store.get(stage_key) == b"synthetic encrypted stage"
    late_key = str(uuid.uuid4())
    store.put(late_key, b"late encrypted worker output")
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        job.state = "deleted"
        job.lease_until = None
        enqueue_object_cleanup(db, [late_key], owner_id)
        slot = db.get(UserWorkSlot, owner_id)
        if slot:
            db.delete(slot)
        db.commit()

    assert cleanup_tombstones(store) == 0
    with SessionLocal() as db:
        assert db.get(User, owner_id) is None
        assert db.get(Item, item_id) is None
        assert db.get(ObjectCleanup, stage_key) is None
        assert db.get(ObjectCleanup, late_key) is None
    for key in (stage_key, late_key):
        try:
            store.get(key)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("Deleted account object was not removed")

    client.cookies.set("securebox_session", second_cookie)
    assert client.get("/api/v1/me").status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 401


def test_object_cleanup_keeps_failed_deletes_for_retry(client):
    from sqlalchemy import select

    from securebox.database import SessionLocal
    from securebox.jobs.common import enqueue_object_cleanup
    from securebox.jobs.maintenance import cleanup_pending_objects
    from securebox.models import ObjectCleanup

    key = str(uuid.uuid4())
    with SessionLocal() as db:
        enqueue_object_cleanup(db, [key], None)
        db.commit()

    class FlakyStore:
        fail = True
        deleted: list[str] = []

        def delete(self, object_key: str) -> None:
            if self.fail:
                raise OSError("temporary failure")
            self.deleted.append(object_key)

    store = FlakyStore()
    assert cleanup_pending_objects(store) == 1
    with SessionLocal() as db:
        assert db.scalar(select(ObjectCleanup.object_key).where(ObjectCleanup.object_key == key)) == key
    store.fail = False
    assert cleanup_pending_objects(store) == 0
    assert store.deleted == [key]
    with SessionLocal() as db:
        assert db.get(ObjectCleanup, key) is None


def test_items_cursor_returns_every_page_without_overlap(client):
    from securebox.config import get_settings
    from securebox.database import SessionLocal
    from securebox.envelope import metadata_aad, seal_metadata
    from securebox.models import Item, User
    from sqlalchemy import select

    username, _password, headers = _register_and_login(client)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        assert user is not None
        owner_id = user.id
        settings = get_settings()
        items = []
        for index in range(55):
            item_id = str(uuid.uuid4())
            name = f"synthetic-page-{index:02d}.json"
            metadata = {
                "original_filename": name,
                "content_type": "application/json",
                "kind": "profile",
                "sha256": "0" * 64,
            }
            envelope = seal_metadata(metadata, settings.kek_v1, metadata_aad(owner_id, item_id))
            items.append(Item(
                id=item_id,
                owner_id=owner_id,
                kind="profile",
                status="complete",
                original_size=16,
                metadata_envelope=envelope,
                created_at=base + timedelta(seconds=index),
            ))
        db.add_all(items)
        db.commit()

    first = client.get("/api/v1/items?limit=50", headers=headers)
    assert first.status_code == 200, first.text
    page_one = first.json()
    assert len(page_one["items"]) == 50
    assert page_one["next_cursor"]
    second = client.get(f"/api/v1/items?limit=50&cursor={page_one['next_cursor']}", headers=headers)
    assert second.status_code == 200, second.text
    page_two = second.json()
    assert len(page_two["items"]) == 5
    assert page_two["next_cursor"] is None
    ids = [row["id"] for row in page_one["items"] + page_two["items"]]
    assert len(ids) == len(set(ids)) == 55


def test_api_keys_are_not_exposed_or_accepted(client):
    _username, _password, headers = _register_and_login(client)
    assert client.get("/api/v1/keys", headers=headers).status_code == 404
    assert client.post("/api/v1/keys", json={"level": "metadata-read"}, headers=headers).status_code == 404
    assert client.delete("/api/v1/keys/unused", headers=headers).status_code == 404

    client.cookies.set("securebox_session", "invalid")
    bearer_only = client.get("/api/v1/items", headers={"Authorization": "Bearer sbk_removed"})
    assert bearer_only.status_code == 401
    assert bearer_only.json()["error"]["code"] == "unauthenticated"


def test_file_upload_creates_all_variants_and_downloads_exact_bytes(client):
    _username, _password, headers = _register_and_login(client)
    source = _png()
    response = client.post(
        "/api/v1/files",
        files={"file": ("identity.png", source, "image/png")},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    item_id, job_id = response.json()["item_id"], response.json()["job_id"]
    job = _wait_for_job(client, job_id, headers)
    assert job["status"] == "complete", job

    variants = client.get(f"/api/v1/items/{item_id}/variants", headers=headers)
    assert variants.status_code == 200, variants.text
    rows = variants.json()["variants"]
    assert {row["algorithm"] for row in rows} == {"aes", "des", "rc4"}
    assert all(row["ciphertext_bytes"] > 0 for row in rows)

    preview = client.get(f"/api/v1/items/{item_id}/variants/aes/ciphertext", headers=headers)
    assert preview.status_code == 200, preview.text
    assert preview.json()["preview_bytes"] <= 64
    assert "key" not in preview.json()

    downloaded = client.get(f"/api/v1/items/{item_id}/variants/aes/download", headers=headers)
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == source
    assert "attachment" in downloaded.headers["content-disposition"]

    queued = client.post(f"/api/v1/items/{item_id}/benchmarks", headers=headers)
    assert queued.status_code == 202, queued.text
    benchmark = _wait_for_benchmark(client, queued.json()["run_id"], headers)
    assert benchmark["status"] == "complete", benchmark
    assert {key for key in benchmark["results"] if key in {"aes", "des", "rc4"}} == {"aes", "des", "rc4"}
    assert all(benchmark["results"][key]["sample_count"] == 5 for key in ("aes", "des", "rc4"))
    assert "obsolete" in benchmark["results"]["analysis"]
    deleted = client.delete(f"/api/v1/items/{item_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    hidden_results = client.get(f"/api/v1/benchmark-runs/{queued.json()['run_id']}", headers=headers)
    assert hidden_results.status_code == 200
    assert hidden_results.json()["status"] == "deleted"
    assert hidden_results.json()["results"] is None


def test_deleted_item_during_benchmark_cannot_receive_saved_results(client, monkeypatch):
    from securebox import runtime
    from securebox.database import SessionLocal
    from securebox.jobs.benchmark import process_benchmark
    from securebox.models import BenchmarkRun, Item, User, UserWorkSlot

    username, _password, headers = _register_and_login(client, "benchmarkdelete")
    uploaded = client.post(
        "/api/v1/files",
        files={"file": ("identity.png", _png(), "image/png")},
        headers=headers,
    )
    assert uploaded.status_code == 202, uploaded.text
    item_id, job_id = uploaded.json()["item_id"], uploaded.json()["job_id"]
    assert _wait_for_job(client, job_id, headers)["status"] == "complete"

    # Keep the app worker from claiming this manually-created benchmark. The
    # test drives it directly so deletion can happen at a precise point.
    monkeypatch.setattr(runtime, "run_worker_once", lambda *_args: False)
    run_id = str(uuid.uuid4())
    with SessionLocal() as db:
        owner = db.query(User).filter(User.username == username).one()
        owner_id = owner.id
        db.add_all(
            (
                BenchmarkRun(id=run_id, owner_id=owner_id, item_id=item_id, state="queued"),
                UserWorkSlot(owner_id=owner_id, work_id=run_id, work_type="benchmark"),
            )
        )
        db.commit()

    entered_benchmark = threading.Event()
    resume_benchmark = threading.Event()
    worker_errors: list[BaseException] = []

    class PausedCrypto:
        def benchmark(self, _algorithm, _plaintext, samples=5):
            entered_benchmark.set()
            if not resume_benchmark.wait(timeout=15):
                raise TimeoutError("benchmark test was not released")
            return {"backend": "pycryptodome", "sample_count": samples, "encrypt_ns": 1}

    def process():
        try:
            process_benchmark(run_id, client.app.state.settings, client.app.state.store, PausedCrypto())
        except BaseException as exc:  # surfaced in the main test thread below
            worker_errors.append(exc)

    thread = threading.Thread(target=process, daemon=True)
    thread.start()
    try:
        assert entered_benchmark.wait(timeout=15), "benchmark worker did not reach the paused benchmark call"
        deleted = client.delete(f"/api/v1/items/{item_id}", headers=headers)
        assert deleted.status_code == 204, deleted.text
    finally:
        resume_benchmark.set()
        thread.join(timeout=15)

    assert not thread.is_alive(), "benchmark worker did not finish"
    assert worker_errors == []
    public_run = client.get(f"/api/v1/benchmark-runs/{run_id}", headers=headers)
    assert public_run.status_code == 200
    assert public_run.json()["status"] == "deleted"
    assert public_run.json()["results"] is None
    with SessionLocal() as db:
        run = db.get(BenchmarkRun, run_id)
        item = db.get(Item, item_id)
        owner = db.get(User, owner_id)
        assert run is not None and run.state == "deleted"
        assert run.result_json is None
        assert item is not None and item.status == "deleted"
        assert owner is not None and owner.deleted_at is None
        assert db.get(UserWorkSlot, owner_id) is None


def test_profile_snapshot_is_encrypted_and_read_only_after_processing(client):
    _username, _password, headers = _register_and_login(client)
    missing_profile = client.get("/api/v1/me/profile?algorithm=aes", headers=headers)
    assert missing_profile.status_code == 404
    assert missing_profile.json()["error"]["code"] == "profile_not_found"
    assert "Save a profile first" in missing_profile.json()["error"]["message"]
    saved = client.put(
        "/api/v1/me/profile",
        json={"display_name": "Synthetic Identity", "national_id": "FAKE-0000"},
        headers=headers,
    )
    assert saved.status_code == 202, saved.text
    job = _wait_for_job(client, saved.json()["job_id"], headers)
    assert job["status"] == "complete", job
    loaded = client.get("/api/v1/me/profile?algorithm=aes", headers=headers)
    assert loaded.status_code == 200, loaded.text
    assert loaded.json()["profile"] == {"display_name": "Synthetic Identity", "national_id": "FAKE-0000"}


def test_enqueue_rechecks_cached_owner_after_tombstone(client):
    import pytest

    from sqlalchemy import select

    from securebox.database import SessionLocal
    from securebox.domain.errors import DomainError
    from securebox.models import User, now_utc
    from securebox.security import Principal
    from securebox.services.items import _queue_item

    username, _password, _headers = _register_and_login(client, "staleowner")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        assert user is not None and user.deleted_at is None
        principal = Principal(user.id, user.username)

        # Simulate a concurrent account deletion while this session still has
        # the authenticated owner in its identity map (expire_on_commit=False).
        db.execute(User.__table__.update().where(User.id == user.id).values(deleted_at=now_utc()))
        assert user.deleted_at is None

        with pytest.raises(DomainError) as raised:
            _queue_item(
                db,
                client.app.state.settings,
                client.app.state.store,
                principal,
                "profile",
                b"synthetic profile",
                {"original_filename": "fixture.json"},
            )
        assert raised.value.code == "not_found"
        assert user.deleted_at is not None
        db.rollback()


def test_uploaded_resources_are_invisible_to_other_accounts(client):
    owner, owner_password, owner_headers = _register_and_login(client, "owner")
    accepted = client.put("/api/v1/me/profile", json={"display_name": "Private Synthetic Name"}, headers=owner_headers)
    assert accepted.status_code == 202, accepted.text
    item_id, job_id = accepted.json()["item_id"], accepted.json()["job_id"]

    logout = client.post("/api/v1/auth/logout", headers=owner_headers)
    assert logout.status_code == 204
    _other, other_password, other_headers = _register_and_login(client, "other")
    assert client.get(f"/api/v1/items/{item_id}", headers=other_headers).status_code == 404
    assert client.get(f"/api/v1/jobs/{job_id}", headers=other_headers).status_code == 404
    assert client.get("/api/v1/items", headers=other_headers).json()["items"] == []

    client.post("/api/v1/auth/logout", headers=other_headers)
    login = client.post("/api/v1/auth/login", json={"username": owner, "password": owner_password})
    assert login.status_code == 200
    owner_headers = {"Origin": "http://testserver", "X-CSRF-Token": login.json()["csrf_token"]}
    assert client.get(f"/api/v1/items/{item_id}", headers=owner_headers).status_code == 200


def test_upload_rejects_unsupported_and_mismatched_content(client):
    _username, _password, headers = _register_and_login(client)
    unsupported = client.post(
        "/api/v1/files",
        files={"file": ("payload.svg", b"<svg/>", "image/svg+xml")},
        headers=headers,
    )
    assert unsupported.status_code == 415
    assert unsupported.json()["error"]["code"] == "unsupported_file_type"
    assert "JPG, JPEG, PNG, PDF, DOCX, XLSX, or MP4" in unsupported.json()["error"]["message"]

    mismatch = client.post(
        "/api/v1/files",
        files={"file": ("identity.png", b"not png", "image/png")},
        headers=headers,
    )
    assert mismatch.status_code == 415
    assert mismatch.json()["error"]["code"] == "invalid_file"

    unexpected_field = client.post(
        "/api/v1/files",
        files={"file": ("identity.png", _png(), "image/png")},
        data={"owner_id": "attacker-selected"},
        headers=headers,
    )
    assert unexpected_field.status_code == 400

    multiple_files = client.post(
        "/api/v1/files",
        files=[
            ("file", ("identity.png", _png(), "image/png")),
            ("file", ("second.png", _png(), "image/png")),
        ],
        headers=headers,
    )
    assert multiple_files.status_code == 400


def test_multipart_body_limit_returns_well_formed_413(client):
    _username, _password, headers = _register_and_login(client)
    oversized = client.post(
        "/api/v1/files",
        files={"file": ("movie.mp4", b"x" * (20 * 1024 * 1024 + 128 * 1024), "video/mp4")},
        headers=headers,
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "request_too_large"
    assert "smaller file" in oversized.json()["error"]["message"]
    assert oversized.json()["error"]["request_id"] == oversized.headers["x-request-id"]


def test_failed_background_job_returns_a_safe_explanation_and_recovery_step(client):
    from securebox.database import SessionLocal
    from securebox.models import Item, Job

    _username, _password, headers = _register_and_login(client)
    response = client.post(
        "/api/v1/files",
        files={"file": ("identity.png", _png(), "image/png")},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    item_id, job_id = response.json()["item_id"], response.json()["job_id"]
    assert _wait_for_job(client, job_id, headers)["status"] == "complete"

    # Exercise the failed-job response deterministically without depending on a
    # particular machine's assembly backend or worker timing.
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        item = db.get(Item, item_id)
        job.state = item.status = "failed"
        job.error_code = "native_backend_failed"
        db.commit()

    job_error = client.get(f"/api/v1/jobs/{job_id}", headers=headers).json()
    assert job_error["error_message"] == "Encryption couldn't finish on this server. Try uploading again later. If it keeps failing, contact the project maintainer."
    assert "CryptoProvider" not in job_error["error_message"]
    item_error = client.get("/api/v1/items", headers=headers).json()["items"][0]
    assert item_error["error_message"] == job_error["error_message"]


def test_error_message_catalog_covers_validation_and_worker_failures():
    from starlette.requests import Request

    from fastapi import HTTPException
    from securebox.api.errors import ERROR_MESSAGES, error_message, http_error_handler, public_error_code

    expected_codes = {
        "invalid_filename", "invalid_file", "file_too_large", "unsupported_file_type", "mime_mismatch",
        "image_dimensions_exceeded", "invalid_office_file", "archive_limits_exceeded", "active_office_content",
        "external_relationship", "active_pdf_content", "invalid_mp4", "video_limits_exceeded",
        "video_validation_unavailable", "payload_integrity_mismatch", "processing_failed", "native_backend_failed",
        "retry_limit_exceeded", "benchmark_failed",
    }
    assert expected_codes <= ERROR_MESSAGES.keys()
    assert all(isinstance(ERROR_MESSAGES[code], str) and len(ERROR_MESSAGES[code]) > 20 for code in expected_codes)
    assert error_message("unrecognized_internal_detail") == ERROR_MESSAGES["internal_error"]
    assert "Sign in" in ERROR_MESSAGES["registration_closed"]
    assert "project maintainer" in ERROR_MESSAGES["registration_closed"]
    assert "Reload the page" in ERROR_MESSAGES["session_check_failed"]
    assert public_error_code("unrecognized_internal_detail") == "internal_error"

    request = Request({"type": "http", "headers": [], "state": {}})
    response = asyncio.run(http_error_handler(
        request,
        HTTPException(500, detail={"code": "internal_secret_config_name"}),
    ))
    payload = json.loads(response.body)
    assert payload["error"]["code"] == "internal_error"
    assert "internal_secret_config_name" not in response.body.decode()
