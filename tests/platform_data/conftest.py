"""Shared fixtures for the platform-data conformance suite (CONTRACTS.md §4).

The SAME test cases run against the reference
:class:`~tessera.db.memory.InMemoryDatabase` and the rewritten
:class:`~tessera.db.sql.SQLDatabase` (SQLite + aiosqlite, file-backed
per test so concurrent connections behave like a real server). MongoDB and
DynamoDB adapters get dedicated unit-level tests with mocked/stubbed
clients (no live servers required).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from tessera.db import InMemoryDatabase
from tessera.db.sql import SQLDatabase

__all__ = [
    "db",
    "to_datetime",
    "expected_checksum",
]


def _to_datetime(value: Any) -> datetime:
    """Normalize backend timestamps (aware datetime or ISO-8601 string)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _expected_checksum(record: dict) -> str:
    """Recompute the audit checksum independently of the implementation.

    memory.py semantics: sha256 over canonical JSON (sort_keys, compact
    separators, default=str) of the event WITHOUT db-assigned fields
    (``id``, ``sequence``, ``checksum``); ``previous_checksum`` is part of
    the checksummed payload.
    """
    payload = {
        key: value
        for key, value in record.items()
        if key not in {"id", "sequence", "checksum"}
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.fixture(scope="session")
def to_datetime():
    """Timestamp normalizer shared by all conformance tests."""
    return _to_datetime


@pytest.fixture(scope="session")
def expected_checksum():
    """Reference audit checksum recomputation (memory.py semantics)."""
    return _expected_checksum


@pytest.fixture(params=["memory", "sql-sqlite"], scope="function")
async def db(request, tmp_path):
    """A connected database backend; fresh per test."""
    if request.param == "memory":
        database = InMemoryDatabase()
    else:
        db_file = tmp_path / f"conformance-{uuid.uuid4().hex}.sqlite"
        database = SQLDatabase(f"sqlite+aiosqlite:///{db_file}")
    await database.connect()
    try:
        yield database
    finally:
        await database.close()
