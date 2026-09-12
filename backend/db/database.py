"""
backend/db/database.py
======================
AEGIS — Async SQLAlchemy engine + session factory.

Reads DATABASE_URL from the environment (or .env via python-dotenv).
Falls back to a local SQLite file if not set, so the system works offline
and in CI without any configuration.

Supported URL schemes
---------------------
    postgresql+asyncpg://...   — NeonDB / any PostgreSQL (Phase 5 multi-VM)
    sqlite+aiosqlite:///...    — local SQLite (dev / offline fallback)

Usage
-----
    from backend.db.database import get_session, init_db

    # In FastAPI lifespan:
    await init_db()

    # In an endpoint:
    async with get_session() as session:
        session.add(SomeModel(...))
        await session.commit()
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
import socket
import logging

logger = logging.getLogger(__name__)

# DNS fallback for cloud databases (helps on networks where local router DNS fails CNAMEs)
_orig_getaddrinfo = socket.getaddrinfo

def _aegis_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror:
        if isinstance(host, str) and "neon.tech" in host:
            try:
                import dns.resolver
                res = dns.resolver.Resolver()
                res.nameservers = ["8.8.8.8", "1.1.1.1"]
                answers = res.resolve(host, "A")
                results = []
                for rdata in answers:
                    results.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (rdata.address, port)))
                if results:
                    return results
            except Exception:
                pass
        raise

socket.getaddrinfo = _aegis_getaddrinfo

# ---------------------------------------------------------------------------
# Load .env (project root)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_PROJECT_ROOT / ".env")

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{_PROJECT_ROOT / 'aegis_local.db'}",
)

# asyncpg doesn't accept the bare ?sslmode=require that psycopg2 uses;
# it needs ssl=require in the query string. We normalise here so the .env
# can use either form.
_connect_args: dict = {}
if DATABASE_URL.startswith("postgresql"):
    if "sslmode=require" in DATABASE_URL and "ssl=require" not in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.replace("sslmode=require", "ssl=require")
    # strip channel_binding parameter — asyncpg doesn't understand it
    if "channel_binding=require" in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.replace("&channel_binding=require", "").replace("?channel_binding=require", "")
    _connect_args = {"ssl": "require"}

engine = create_async_engine(
    DATABASE_URL,
    echo=False,          # set True to log every SQL statement during dev
    pool_pre_ping=True,  # detect stale connections (important for NeonDB idle timeout)
    connect_args=_connect_args if DATABASE_URL.startswith("postgresql") else {},
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ---------------------------------------------------------------------------
# Base for ORM models
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------
@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager yielding a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """
    Create all tables that don't exist yet.
    Called once from FastAPI's lifespan handler.
    """
    # Import models so SQLAlchemy registers them against Base.metadata
    import backend.db.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
