"""Conformance: organizations/members/invitations + audit hash chain."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from authy_package.db import InMemoryDatabase
from authy_package.db.abstract_db import AbstractDatabase
from authy_package.db.sql import SQLDatabase
from authy_package.errors import IntegrityError



@pytest.fixture
async def org(db: AbstractDatabase) -> dict:
    return await db.create_organization({"name": "Acme Corp"})


class TestOrganizations:
    async def test_create_defaults_slug_and_id(
        self, db: AbstractDatabase, to_datetime
    ) -> None:
        created = await db.create_organization({"name": "Acme Corp!"})
        assert created["id"]
        assert created["slug"] == "acme-corp"
        assert to_datetime(created["created_at"]).tzinfo is not None

    async def test_name_required(self, db: AbstractDatabase) -> None:
        with pytest.raises(ValueError):
            await db.create_organization({})

    async def test_duplicate_slug_rejected(self, db: AbstractDatabase) -> None:
        await db.create_organization({"name": "Acme"})
        with pytest.raises(IntegrityError):
            await db.create_organization({"name": "ACME"})

    async def test_get_by_id_and_slug(self, db: AbstractDatabase, org: dict) -> None:
        assert (await db.get_organization(org["id"]))["id"] == org["id"]
        assert (await db.get_organization_by_slug("acme-corp"))["id"] == org["id"]
        assert await db.get_organization_by_slug("missing") is None
        assert await db.get_organization("missing") is None

    async def test_update_and_slug_reindex(self, db: AbstractDatabase, org: dict) -> None:
        updated = await db.update_organization(
            org["id"], {"name": "Acme Inc", "slug": "acme-inc"}
        )
        assert updated["slug"] == "acme-inc"
        assert await db.get_organization_by_slug("acme-corp") is None
        assert (await db.get_organization_by_slug("acme-inc"))["id"] == org["id"]

    async def test_update_conflicting_slug_rejected(
        self, db: AbstractDatabase
    ) -> None:
        await db.create_organization({"name": "One"})
        second = await db.create_organization({"name": "Two"})
        with pytest.raises(IntegrityError):
            await db.update_organization(second["id"], {"slug": "one"})

    async def test_list_pagination(self, db: AbstractDatabase) -> None:
        for i in range(3):
            await db.create_organization({"name": f"Org {i}"})
        rows, total = await db.list_organizations(limit=2, offset=0)
        assert len(rows) == 2 and total == 3
        rows, total = await db.list_organizations(limit=2, offset=2)
        assert len(rows) == 1 and total == 3

    async def test_delete_cascades_members_and_invitations(
        self, db: AbstractDatabase, org: dict
    ) -> None:
        await db.add_org_member(org["id"], {"user_id": "u1"})
        await db.create_invitation({"org_id": org["id"], "email": "x@y.test"})
        assert await db.delete_organization(org["id"]) is True
        assert await db.get_org_members(org["id"]) == []
        assert await db.get_pending_invitations(org["id"]) == []
        assert await db.delete_organization(org["id"]) is False


class TestMembersAndInvitations:
    async def test_member_lifecycle(
        self, db: AbstractDatabase, org: dict, to_datetime
    ) -> None:
        member = await db.add_org_member(org["id"], {"user_id": "u1"})
        assert member["role"] == "member"
        assert to_datetime(member["added_at"]).tzinfo is not None
        with pytest.raises(IntegrityError):
            await db.add_org_member(org["id"], {"user_id": "u1"})
        updated = await db.update_org_member(org["id"], "u1", {"role": "admin"})
        assert updated["role"] == "admin"
        assert await db.update_org_member(org["id"], "ghost", {"role": "x"}) is None
        assert await db.remove_org_member(org["id"], "u1") is True
        assert await db.remove_org_member(org["id"], "u1") is False
        assert await db.get_org_members(org["id"]) == []

    async def test_member_validation(self, db: AbstractDatabase, org: dict) -> None:
        with pytest.raises(ValueError):
            await db.add_org_member(org["id"], {"role": "admin"})
        with pytest.raises(IntegrityError):
            await db.add_org_member("missing-org", {"user_id": "u1"})
        await db.add_org_member(org["id"], {"user_id": "u1"})
        with pytest.raises(ValueError):
            await db.update_org_member(org["id"], "u1", {"user_id": "u2"})

    async def test_invitation_lifecycle(self, db: AbstractDatabase, org: dict) -> None:
        first = await db.create_invitation(
            {"org_id": org["id"], "email": "a@y.test"}
        )
        assert first["id"] and first["token"]
        assert first["status"] == "pending"
        second = await db.create_invitation(
            {"org_id": org["id"], "email": "b@y.test"}
        )
        await db.create_invitation(
            {"org_id": org["id"], "email": "c@y.test", "status": "accepted"}
        )
        found = await db.get_invitation_by_token(first["token"])
        assert found["id"] == first["id"]
        assert await db.get_invitation_by_token("bogus") is None
        pending = await db.get_pending_invitations(org["id"])
        assert {i["id"] for i in pending} == {first["id"], second["id"]}
        assert await db.delete_invitation(first["id"]) is True
        assert await db.delete_invitation(first["id"]) is False
        with pytest.raises(IntegrityError):
            await db.create_invitation({"org_id": "missing", "email": "x@y.test"})


async def _seed_events(db: AbstractDatabase, count: int = 5) -> list:
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


class TestAuditChain:
    async def test_chain_links_genesis_and_sequences(
        self, db: AbstractDatabase, to_datetime
    ) -> None:
        events = await _seed_events(db)
        assert events[0]["previous_checksum"] == "0" * 64
        assert [e["sequence"] for e in events] == [1, 2, 3, 4, 5]
        for previous, current in zip(events, events[1:]):
            assert current["previous_checksum"] == previous["checksum"]
        assert to_datetime(events[0]["timestamp"]).tzinfo is not None

    async def test_checksums_match_reference_semantics(
        self, db: AbstractDatabase, expected_checksum
    ) -> None:
        events = await _seed_events(db)
        for event in events:
            assert expected_checksum(event) == event["checksum"]
            fetched = await db.get_audit_event(event["id"])
            assert expected_checksum(fetched) == fetched["checksum"]

    async def test_bulk_save_preserves_order(self, db: AbstractDatabase) -> None:
        count = await db.save_audit_events(
            [{"event_type": "bulk", "actor": f"a{i}"} for i in range(3)]
        )
        assert count == 3
        rows, total = await db.search_audit_events(event_types=["bulk"])
        assert total == 3
        assert [r["sequence"] for r in rows] == [3, 2, 1]  # newest first

    async def test_tamper_detection(self, db: AbstractDatabase, expected_checksum) -> None:
        """Mutating a stored event must break its checksum.

        memory: mutate the stored dict directly; sql: UPDATE the row's
        payload. Either way, recomputation no longer matches.
        """
        events = await _seed_events(db)
        victim = events[2]
        if isinstance(db, InMemoryDatabase):
            db._audit_chain[2]["actor"] = "evil-admin"
            assert await db.verify_audit_chain() is False
        elif isinstance(db, SQLDatabase):
            from sqlalchemy import update as sa_update

            from authy_package.db.sql import _AuditEventModel

            tampered_data = {
                key: value
                for key, value in victim.items()
                if key not in {"id", "sequence", "checksum", "previous_checksum"}
            }
            tampered_data["actor"] = "evil-admin"
            async with db._session_factory() as session:  # type: ignore[misc]
                async with session.begin():
                    await session.execute(
                        sa_update(_AuditEventModel)
                        .where(_AuditEventModel.id == victim["id"])
                        .values(data=tampered_data)
                    )
            tampered = await db.get_audit_event(victim["id"])
            assert tampered["actor"] == "evil-admin"
            assert expected_checksum(tampered) != tampered["checksum"]

    async def test_search_filters_and_time_bounds(
        self, db: AbstractDatabase, to_datetime
    ) -> None:
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
        assert to_datetime(rows[0]["timestamp"]) >= to_datetime(rows[1]["timestamp"])

        now = datetime.now(timezone.utc)
        rows, total = await db.search_audit_events(
            start=now - timedelta(minutes=1), end=now + timedelta(minutes=1)
        )
        assert total == 6
        rows, total = await db.search_audit_events(start=now + timedelta(hours=1))
        assert total == 0

    async def test_delete_before(self, db: AbstractDatabase) -> None:
        await _seed_events(db, 4)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        deleted = await db.delete_audit_events_before(future)
        assert deleted == 4
        assert await db.search_audit_events() == ([], 0)

    async def test_statistics(self, db: AbstractDatabase) -> None:
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

    async def test_time_series_buckets(self, db: AbstractDatabase) -> None:
        await _seed_events(db, 4)
        since = datetime.now(timezone.utc) - timedelta(seconds=60)
        series = await db.get_audit_time_series(since=since, bucket_seconds=30)
        assert len(series) >= 2
        assert sum(bucket["count"] for bucket in series) == 4
        for bucket in series:
            assert bucket["bucket_start"].tzinfo is not None
        with pytest.raises(ValueError):
            await db.get_audit_time_series(
                since=datetime.now(timezone.utc), bucket_seconds=0
            )
