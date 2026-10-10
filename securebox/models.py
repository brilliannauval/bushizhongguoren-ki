from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    items: Mapped[list["Item"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    csrf_digest: Mapped[bytes] = mapped_column(LargeBinary(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    __table_args__ = (Index("ix_sessions_last_seen", "last_seen_at"),)


class Item(Base):
    __tablename__ = "items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    original_size: Mapped[int] = mapped_column(BigInteger)
    metadata_envelope: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    owner: Mapped[User] = relationship(back_populates="items")
    variants: Mapped[list["CipherVariant"]] = relationship(back_populates="item", cascade="all, delete-orphan")
    job: Mapped["Job | None"] = relationship(back_populates="item", cascade="all, delete-orphan", uselist=False)
    __table_args__ = (
        CheckConstraint("kind IN ('file', 'profile')", name="ck_items_kind"),
        CheckConstraint("status IN ('queued', 'processing', 'complete', 'failed', 'deleted')", name="ck_items_status"),
        Index("ix_items_owner_created", "owner_id", "created_at"),
        Index("ix_items_owner_status", "owner_id", "status"),
        Index("ix_items_owner_kind_status_created", "owner_id", "kind", "status", "created_at"),
    )


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    item_id: Mapped[str] = mapped_column(ForeignKey("items.id", ondelete="CASCADE"), unique=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    staging_object_key: Mapped[str] = mapped_column(String(80))
    staging_wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    idempotency_key: Mapped[str] = mapped_column(String(36), unique=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    item: Mapped[Item] = relationship(back_populates="job")
    __table_args__ = (
        CheckConstraint("state IN ('queued', 'processing', 'complete', 'failed', 'deleted')", name="ck_jobs_state"),
        Index("ix_jobs_state_created", "state", "created_at"),
    )


class UserWorkSlot(Base):
    __tablename__ = "user_work_slots"
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    work_id: Mapped[str] = mapped_column(String(36), unique=True)
    work_type: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class CipherVariant(Base):
    __tablename__ = "cipher_variants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    item_id: Mapped[str] = mapped_column(ForeignKey("items.id", ondelete="CASCADE"), index=True)
    algorithm: Mapped[str] = mapped_column(String(8))
    mode: Mapped[str] = mapped_column(String(32))
    backend: Mapped[str] = mapped_column(String(32))
    crypto_version: Mapped[str] = mapped_column(String(32))
    object_key: Mapped[str] = mapped_column(String(80), unique=True)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    byte_count: Mapped[int] = mapped_column(BigInteger)
    digest_sha256: Mapped[str] = mapped_column(String(64))
    encrypt_ms: Mapped[float] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    item: Mapped[Item] = relationship(back_populates="variants")
    __table_args__ = (
        UniqueConstraint("item_id", "algorithm", name="uq_variant_item_algorithm"),
        CheckConstraint("algorithm IN ('aes', 'des', 'rc4')", name="ck_variant_algorithm"),
    )


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    item_id: Mapped[str] = mapped_column(ForeignKey("items.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    warmups: Mapped[int] = mapped_column(Integer, default=1)
    sample_count: Mapped[int] = mapped_column(Integer, default=5)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    __table_args__ = (Index("ix_benchmark_owner_item_created", "owner_id", "item_id", "created_at"),)


class RateCounter(Base):
    __tablename__ = "rate_counters"
    subject_digest: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    action: Mapped[str] = mapped_column(String(32), primary_key=True)
    window_start: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (Index("ix_rate_counters_window", "window_start"),)


class ObjectCleanup(Base):
    """Durable, idempotent cleanup work for opaque encrypted object keys."""

    __tablename__ = "object_cleanup"
    object_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    # Intentionally not a foreign key: cleanup must survive account/item cascades.
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
