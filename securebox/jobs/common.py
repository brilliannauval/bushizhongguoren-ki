from __future__ import annotations

from sqlalchemy import func

from ..models import ObjectCleanup, UserWorkSlot, now_utc

ALGORITHMS = ("aes", "des", "rc4")
MODE_BY_ALGORITHM = {"aes": "AES-128-CBC/PKCS7", "des": "DES-CBC/PKCS7", "rc4": "RC4"}


def _release_slot(db, owner_id: str, work_id: str) -> None:
    slot = db.get(UserWorkSlot, owner_id)
    if slot and slot.work_id == work_id:
        db.delete(slot)


def enqueue_object_cleanup(db, object_keys: list[str] | tuple[str, ...], owner_id: str | None) -> None:
    """Persist opaque object keys before their owning database rows disappear."""
    keys = list(dict.fromkeys(key for key in object_keys if key))
    if not keys:
        return
    table = ObjectCleanup.__table__
    values = [{"object_key": key, "owner_id": owner_id, "created_at": now_utc()} for key in keys]
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    elif dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        for value in values:
            existing = db.get(ObjectCleanup, value["object_key"])
            if existing is None:
                db.add(ObjectCleanup(**value))
            elif existing.owner_id is None:
                existing.owner_id = owner_id
        return
    statement = insert(table).values(values)
    excluded = statement.excluded
    statement = statement.on_conflict_do_update(
        index_elements=[table.c.object_key],
        set_={"owner_id": func.coalesce(table.c.owner_id, excluded.owner_id)},
    )
    db.execute(statement)
