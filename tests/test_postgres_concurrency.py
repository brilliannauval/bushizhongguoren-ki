from __future__ import annotations

import os
import threading
import uuid

import pytest
from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, create_engine, insert, select

from securebox.jobs.leases import claim_lease


def test_postgres_concurrent_claims_have_exactly_one_winner():
    database_url = os.getenv("TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set TEST_POSTGRES_URL to run PostgreSQL race tests")
    engine = create_engine(database_url, pool_size=2)
    table_name = f"lease_race_{uuid.uuid4().hex}"
    claims = Table(
        table_name,
        MetaData(),
        Column("id", String(36), primary_key=True),
        Column("state", String(16), nullable=False),
        Column("attempt_count", Integer, nullable=False),
        Column("lease_until", DateTime(timezone=True)),
        Column("lease_token", String(36)),
    )
    claims.create(engine)
    work_id = str(uuid.uuid4())
    with engine.begin() as connection:
        connection.execute(
            insert(claims).values(id=work_id, state="queued", attempt_count=0)
        )

    barrier = threading.Barrier(2)
    winners: list[str | None] = []

    def try_claim():
        with engine.begin() as connection:
            barrier.wait(timeout=10)
            winners.append(
                claim_lease(
                    connection,
                    claims,
                    work_id,
                    max_attempts=3,
                    lease_seconds=300,
                )
            )

    threads = [threading.Thread(target=try_claim) for _ in range(2)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        assert all(not thread.is_alive() for thread in threads)
        assert sum(token is not None for token in winners) == 1
        with engine.connect() as connection:
            attempts, token = connection.execute(
                select(claims.c.attempt_count, claims.c.lease_token).where(claims.c.id == work_id)
            ).one()
        assert attempts == 1
        assert token in winners
    finally:
        claims.drop(engine)
        engine.dispose()
