from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def _engine():
    settings = get_settings()
    if settings.database_url.startswith("sqlite:"):
        Path("./var").resolve().mkdir(parents=True, exist_ok=True)
        return create_engine(
            settings.database_url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True,
        )
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=2,
        pool_recycle=300,
        connect_args={
            "sslmode": "disable" if settings.app_env == "development" else "require"
        } if settings.database_url.startswith("postgresql") else {},
    )


engine = _engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
