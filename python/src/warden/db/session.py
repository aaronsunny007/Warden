from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from warden.settings import get_settings


def engine(url: str | None = None) -> Engine:
    u = url or get_settings().database_url
    if not u:
        raise RuntimeError("WARDEN_DATABASE_URL is not set")
    return create_engine(u, pool_pre_ping=True)


def session_factory(url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(engine(url), expire_on_commit=False)
