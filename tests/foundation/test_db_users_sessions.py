"""Tests for §4 InMemoryDatabase: users and sessions."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from tessera.db import InMemoryDatabase
from tessera.errors import IntegrityError


class TestUsers:
    async def test_create_user_defaults(self, db: InMemoryDatabase) -> None:
        user = await db.create_user({"username": "alice", "email": "alice@x.test"})
        assert user["id"]
        assert user["is_active"] is True
        assert user["mfa_enabled"] is False
        assert user["role"] == "user"
        assert user["created_at"].tzinfo is not None
        assert user["created_at"].tzinfo.utcoffset(user["created_at"]) == timezone.utc.utcoffset(None)

    async def test_get_by_id_and_identifier_case_insensitive(
        self, db: InMemoryDatabase
    ) -> None:
        created = await db.create_user(
            {"username": "Alice", "email": "Alice@Example.test", "phone": "+15550001"}
        )
        assert (await db.get_user_by_id(created["id"]))["id"] == created["id"]
        assert (await db.get_user_by_identifier(email="alice@example.TEST"))["id"] == created["id"]
        assert (await db.get_user_by_identifier(username="aLiCe"))["id"] == created["id"]
        assert (await db.get_user_by_identifier(phone="+15550001"))["id"] == created["id"]
        assert await db.get_user_by_identifier(email="missing@x.test") is None

    async def test_duplicate_email_case_insensitive_rejected(
        self, db: InMemoryDatabase
    ) -> None:
        await db.create_user({"username": "u1", "email": "Alice@Example.test"})
        with pytest.raises(IntegrityError):
            await db.create_user({"username": "u2", "email": "alice@example.TEST"})

    async def test_duplicate_username_case_insensitive_rejected(
        self, db: InMemoryDatabase
    ) -> None:
        await db.create_user({"username": "Alice", "email": "a1@x.test"})
        with pytest.raises(IntegrityError):
            await db.create_user({"username": "ALICE", "email": "a2@x.test"})

    async def test_update_user_reindexes_identifiers(self, db: InMemoryDatabase) -> None:
        user = await db.create_user({"username": "alice", "email": "old@x.test"})
        updated = await db.update_user(user["id"], {"email": "new@x.test"})
        assert updated["email"] == "new@x.test"
        assert await db.get_user_by_identifier(email="old@x.test") is None
        assert (await db.get_user_by_identifier(email="NEW@X.TEST"))["id"] == user["id"]

    async def test_update_immutable_fields_rejected(self, db: InMemoryDatabase) -> None:
        user = await db.create_user({"username": "alice", "email": "a@x.test"})
        with pytest.raises(ValueError):
            await db.update_user(user["id"], {"id": "evil"})
        with pytest.raises(ValueError):
            await db.update_user(user["id"], {"created_at": datetime.now(timezone.utc)})

    async def test_update_conflicting_email_rejected(self, db: InMemoryDatabase) -> None:
        await db.create_user({"username": "u1", "email": "one@x.test"})
        other = await db.create_user({"username": "u2", "email": "two@x.test"})
        with pytest.raises(IntegrityError):
            await db.update_user(other["id"], {"email": "ONE@x.test"})

    async def test_update_missing_returns_none(self, db: InMemoryDatabase) -> None:
        assert await db.update_user("missing", {"role": "admin"}) is None

    async def test_delete_user(self, db: InMemoryDatabase) -> None:
        user = await db.create_user({"username": "alice", "email": "a@x.test"})
        assert await db.delete_user(user["id"]) is True
        assert await db.delete_user(user["id"]) is False
        assert await db.get_user_by_identifier(email="a@x.test") is None

    async def test_list_users_pagination_search_filters(self, db: InMemoryDatabase) -> None:
        for i in range(7):
            await db.create_user(
                {
                    "username": f"user{i}",
                    "email": f"user{i}@x.test",
                    "is_active": i % 2 == 0,
                }
            )
        rows, total = await db.list_users(limit=3, offset=0)
        assert len(rows) == 3 and total == 7
        rows2, total2 = await db.list_users(limit=3, offset=6)
        assert len(rows2) == 1 and total2 == 7

        searched, searched_total = await db.list_users(search="USER3")
        assert searched_total == 1
        assert searched[0]["username"] == "user3"

        actives, active_total = await db.list_users(filters={"is_active": True})
        assert active_total == 4
        assert all(r["is_active"] for r in actives)

    async def test_count_users_filters(self, db: InMemoryDatabase) -> None:
        base = datetime.now(timezone.utc)
        for i in range(3):
            await db.create_user(
                {
                    "username": f"u{i}",
                    "email": f"u{i}@x.test",
                    "is_active": i != 0,
                    "mfa_enabled": i == 2,
                }
            )
        assert await db.count_users() == 3
        assert await db.count_users(active_only=True) == 2
        assert await db.count_users(mfa_enabled=True) == 1
        assert await db.count_users(created_since=base) >= 0
        future = datetime(2999, 1, 1, tzinfo=timezone.utc)
        assert await db.count_users(created_since=future) == 0


class TestSessions:
    async def test_save_requires_user_id(self, db: InMemoryDatabase) -> None:
        with pytest.raises(ValueError):
            await db.save_session({"id": "s1"})

    async def test_save_and_get(self, db: InMemoryDatabase) -> None:
        await db.save_session({"id": "s1", "user_id": "u1", "ip": "10.0.0.1"})
        session = await db.get_session("s1")
        assert session["status"] == "active"
        assert session["user_id"] == "u1"
        assert await db.get_session("missing") is None

    async def test_get_active_sessions_filters_status(self, db: InMemoryDatabase) -> None:
        await db.save_session({"id": "s1", "user_id": "u1", "status": "active"})
        await db.save_session({"id": "s2", "user_id": "u1", "status": "revoked"})
        await db.save_session({"id": "s3", "user_id": "u1", "status": "active"})
        await db.save_session({"id": "s4", "user_id": "u2", "status": "active"})
        active = await db.get_active_sessions("u1")
        assert {s["id"] for s in active} == {"s1", "s3"}

    async def test_revoke_session_atomic_flip(self, db: InMemoryDatabase) -> None:
        await db.save_session({"id": "s1", "user_id": "u1", "status": "active"})
        assert await db.revoke_session("s1") is True
        assert await db.revoke_session("s1") is False  # already revoked
        assert await db.revoke_session("missing") is False
        session = await db.get_session("s1")
        assert session["status"] == "revoked"
        assert "revoked_at" in session

    async def test_concurrent_revokes_single_winner(self, db: InMemoryDatabase) -> None:
        await db.save_session({"id": "s1", "user_id": "u1", "status": "active"})
        results = await asyncio.gather(
            db.revoke_session("s1"),
            db.revoke_session("s1"),
            db.revoke_session("s1"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 2

    async def test_revoke_all_user_sessions(self, db: InMemoryDatabase) -> None:
        await db.save_session({"id": "s1", "user_id": "u1", "status": "active"})
        await db.save_session({"id": "s2", "user_id": "u1", "status": "active"})
        await db.save_session({"id": "s3", "user_id": "u1", "status": "revoked"})
        await db.save_session({"id": "s4", "user_id": "u2", "status": "active"})
        assert await db.revoke_all_user_sessions("u1") == 2
        assert await db.get_active_sessions("u1") == []
        assert len(await db.get_active_sessions("u2")) == 1
        assert await db.revoke_all_user_sessions("u1") == 0


class TestLifecycle:
    async def test_connect_health_close(self) -> None:
        db = InMemoryDatabase()
        await db.connect()
        assert await db.health_check() is True
        await db.close()
