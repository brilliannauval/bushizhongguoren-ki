from __future__ import annotations

import time


def test_readiness_reports_cached_storage_and_worker_health(client, monkeypatch):
    deadline = time.monotonic() + 3
    response = None
    while time.monotonic() < deadline:
        response = client.get("/api/v1/health")
        if response.status_code == 200:
            break
        time.sleep(0.05)
    assert response is not None and response.status_code == 200, response.text if response else "no response"
    payload = response.json()
    assert payload["object_storage"] == "ok"
    assert payload["worker"] == "ok"

    calls = 0

    def fail_if_called():
        nonlocal calls
        calls += 1
        raise AssertionError("Storage probing belongs to the background health loop")

    monkeypatch.setattr(client.app.state.store, "check_health", fail_if_called)
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/health").status_code == 200
    assert calls == 0
