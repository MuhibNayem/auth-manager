"""Tests for §4 audit log: checksums, hash chain, search, stats."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from tessera.db import InMemoryDatabase
from tessera.db.memory import GENESIS_CHECKSUM


def _expected_checksum(record: dict) -> str:
    """Recompute the checksum independently of the implementation."""
    payload = {k: v for k, v in record.items() if k not in {"id", "sequence", "checksum"}}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _seed_events(db: InMemoryDatabase, count: int = 5) -> list[dict]:
    stored = []
    for i in range(count):
        stored.append(
            await db.save_audit_event(
                {
                    "event_type": "user.login" if i % 2 == 0 else "user.logout",
                    "actor": f"user-{i}",
                    "target": f"session-{i}",
                    "ip_address": "10.0.0.1",
                    "details": {"index": i},
                }
            )
        )
    return stored


class TestChainIntegrity:
    async def test_first_event_links_to_genesis(self, db: InMemoryDatabase) -> None:
        event = await db.save_audit_event({"event_type": "user.create", "actor": "admin"})
        assert event["previous_checksum"] == GENESIS_CHECKSUM
        assert event["sequence"] == 1
        assert event["id"]
        assert event["timestamp"].tzinfo is not None

    async def test_checksum_excludes_db_assigned_fields(self, db: InMemoryDatabase) -> None:
        event = await db.save_audit_event({"event_type": "user.create", "actor": "admin"})
        # previous_checksum must be part of the checksummed payload.
        assert _expected_checksum(event) == event["checksum"]

    async def test_chain_links_and_verifies(self, db: InMemoryDatabase) -> None:
        events = await _seed_events(db)
        for prev, current in zip(events, events[1:]):
            assert current["previous_checksum"] == prev["checksum"]
        assert events[-1]["sequence"] == len(events)
        assert await db.verify_audit_chain() is True

    async def test_bulk_save_preserves_order(self, db: InMemoryDatabase) -> None:
        count = await db.save_audit_events(
            [{"event_type": "bulk", "actor": f"a{i}"} for i in range(3)]
        )
        assert count == 3
        assert await db.verify_audit_chain() is True

    async def test_tampered_event_detected(self, db: InMemoryDatabase) -> None:
        await _seed_events(db)
        # Mutate a stored event in place (attacker edits the ledger).
        db._audit_chain[2]["actor"] = "evil-admin"
        assert await db.verify_audit_chain() is False

    async def test_tampered_checksum_link_detected(self, db: InMemoryDatabase) -> None:
        await _seed_events(db)
        db._audit_chain[1]["previous_checksum"] = "f" * 64
        assert await db.verify_audit_chain() is False

    async def test_deleted_event_breaks_chain(self, db: InMemoryDatabase) -> None:
        events = await _seed_events(db)
        # Remove a middle event entirely: linkage must fail.
        del db._audit_by_id[events[1]["id"]]
        db._audit_chain.pop(1)
        assert await db.verify_audit_chain() is False

    async def test_get_audit_event_returns_copy(self, db: InMemoryDatabase) -> None:
        stored = await db.save_audit_event({"event_type": "x", "actor": "a"})
        fetched = await db.get_audit_event(stored["id"])
        fetched["actor"] = "mutated-from-outside"
        again = await db.get_audit_event(stored["id"])
        assert again["actor"] == "a"


class TestSearchAndStats:
    async def test_search_filters_and_totals(self, db: InMemoryDatabase) -> None:
        await _seed_events(db, 6)
        rows, total = await db.search_audit_events(event_types=["user.login"])
        assert total == 3
        assert all(r["event_type"] == "user.login" for r in rows)

        rows, total = await db.search_audit_events(actor="user-1")
        assert total == 1 and rows[0]["actor"] == "user-1"

        rows, total = await db.search_audit_events(target="session-2")
        assert total == 1 and rows[0]["target"] == "session-2"

        rows, total = await db.search_audit_events(limit=2, offset=0)
        assert len(rows) == 2 and total == 6
        # newest first
        assert rows[0]["timestamp"] >= rows[1]["timestamp"]

    async def test_search_time_bounds(self, db: InMemoryDatabase) -> None:
        await _seed_events(db, 3)
        now = datetime.now(timezone.utc)
        rows, total = await db.search_audit_events(
            start=now - timedelta(minutes=1), end=now + timedelta(minutes=1)
        )
        assert total == 3
        rows, total = await db.search_audit_events(start=now + timedelta(hours=1))
        assert total == 0

    async def test_delete_before(self, db: InMemoryDatabase) -> None:
        await _seed_events(db, 4)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        deleted = await db.delete_audit_events_before(future)
        assert deleted == 4
        assert await db.search_audit_events() == ([], 0)

    async def test_statistics(self, db: InMemoryDatabase) -> None:
        await _seed_events(db, 5)
        stats = await db.get_audit_statistics()
        assert stats["total_events"] == 5
        assert stats["events_by_type"]["user.login"] == 3
        assert stats["events_by_type"]["user.logout"] == 2
        assert stats["first_event_at"] is not None
        assert stats["last_event_at"] is not None

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        empty = await db.get_audit_statistics(since=future)
        assert empty["total_events"] == 0

    async def test_time_series_buckets(self, db: InMemoryDatabase) -> None:
        await _seed_events(db, 4)
        since = datetime.now(timezone.utc) - timedelta(seconds=60)
        series = await db.get_audit_time_series(since=since, bucket_seconds=30)
        assert len(series) >= 2
        assert sum(bucket["count"] for bucket in series) == 4
        for bucket in series:
            assert bucket["bucket_start"].tzinfo is not None

    async def test_time_series_validates_bucket(self, db: InMemoryDatabase) -> None:
        with pytest.raises(ValueError):
            await db.get_audit_time_series(
                since=datetime.now(timezone.utc), bucket_seconds=0
            )
