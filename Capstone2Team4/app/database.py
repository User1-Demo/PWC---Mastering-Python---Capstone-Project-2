from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine():
    url = get_settings().database_url
    options = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=options, pool_pre_ping=True)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def initialize_database(target_engine=engine) -> None:
    Base.metadata.create_all(bind=target_engine)
    from app.models import AuditChainHead

    with target_engine.begin() as connection:
        if target_engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            connection.execute(
                pg_insert(AuditChainHead)
                .values(id=1, event_hash="0" * 64)
                .on_conflict_do_nothing(index_elements=["id"])
            )
        elif target_engine.dialect.name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            connection.execute(
                sqlite_insert(AuditChainHead)
                .values(id=1, event_hash="0" * 64)
                .on_conflict_do_nothing(index_elements=["id"])
            )
        else:
            raise RuntimeError("CloudGuard supports PostgreSQL and SQLite database engines")
