from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    # SQLite stores datetime without the zone; all writes are normalized to UTC.
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


def make_database(url: str):
    options = {"connect_args": {"check_same_thread": False, "timeout": 15}}
    if url in {"sqlite://", "sqlite:///:memory:"}:
        options["poolclass"] = StaticPool
    engine = create_engine(url, **options)

    @event.listens_for(engine, "connect")
    def sqlite_setup(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.create_function("unicode_casefold", 1, lambda value: (value or "").casefold(), deterministic=True)

    return engine, sessionmaker(bind=engine, expire_on_commit=False)
