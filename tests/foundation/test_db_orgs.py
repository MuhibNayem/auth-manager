"""Tests for §4 organizations, members and invitations."""

from __future__ import annotations

import pytest

from tessera.db import InMemoryDatabase
from tessera.errors import IntegrityError


@pytest.fixture
async def org(db: InMemoryDatabase) -> dict:
    return await db.create_organization({"name": "Acme Corp"})


class TestOrganizations:
    async def test_create_defaults_slug_and_id(self, db: InMemoryDatabase) -> None:
        org = await db.create_organization({"name": "Acme Corp!"})
        assert org["id"]
        assert org["slug"] == "acme-corp"
        assert org["created_at"].tzinfo is not None

    async def test_name_required(self, db: InMemoryDatabase) -> None:
        with pytest.raises(ValueError):
            await db.create_organization({})

    async def test_duplicate_slug_rejected(self, db: InMemoryDatabase) -> None:
        await db.create_organization({"name": "Acme"})
        with pytest.raises(IntegrityError):
            await db.create_organization({"name": "ACME"})

    async def test_get_by_id_and_slug(self, db: InMemoryDatabase, org: dict) -> None:
        assert (await db.get_organization(org["id"]))["id"] == org["id"]
        assert (await db.get_organization_by_slug("acme-corp"))["id"] == org["id"]
        assert await db.get_organization_by_slug("missing") is None
        assert await db.get_organization("missing") is None

    async def test_update_and_slug_reindex(self, db: InMemoryDatabase, org: dict) -> None:
        updated = await db.update_organization(org["id"], {"name": "Acme Inc", "slug": "acme-inc"})
        assert updated["slug"] == "acme-inc"
        assert await db.get_organization_by_slug("acme-corp") is None
        assert (await db.get_organization_by_slug("acme-inc"))["id"] == org["id"]

    async def test_update_conflicting_slug_rejected(self, db: InMemoryDatabase) -> None:
        await db.create_organization({"name": "One"})
        second = await db.create_organization({"name": "Two"})
        with pytest.raises(IntegrityError):
            await db.update_organization(second["id"], {"slug": "one"})

    async def test_update_missing_returns_none(self, db: InMemoryDatabase) -> None:
        assert await db.update_organization("missing", {"name": "x"}) is None

    async def test_list_pagination(self, db: InMemoryDatabase) -> None:
        for i in range(3):
            await db.create_organization({"name": f"Org {i}"})
        rows, total = await db.list_organizations(limit=2, offset=0)
        assert len(rows) == 2 and total == 3
        rows, total = await db.list_organizations(limit=2, offset=2)
        assert len(rows) == 1 and total == 3

    async def test_delete_cascades_members_and_invitations(
        self, db: InMemoryDatabase, org: dict
    ) -> None:
        await db.add_org_member(org["id"], {"user_id": "u1"})
        await db.create_invitation({"org_id": org["id"], "email": "x@y.test"})
        assert await db.delete_organization(org["id"]) is True
        assert await db.get_org_members(org["id"]) == []
        assert await db.get_pending_invitations(org["id"]) == []
        assert await db.delete_organization(org["id"]) is False


class TestMembers:
    async def test_add_member_defaults(self, db: InMemoryDatabase, org: dict) -> None:
        member = await db.add_org_member(org["id"], {"user_id": "u1"})
        assert member["role"] == "member"
        assert member["added_at"].tzinfo is not None

    async def test_member_requires_user_id(self, db: InMemoryDatabase, org: dict) -> None:
        with pytest.raises(ValueError):
            await db.add_org_member(org["id"], {"role": "admin"})

    async def test_member_org_must_exist(self, db: InMemoryDatabase) -> None:
        with pytest.raises(IntegrityError):
            await db.add_org_member("missing-org", {"user_id": "u1"})

    async def test_duplicate_member_rejected(self, db: InMemoryDatabase, org: dict) -> None:
        await db.add_org_member(org["id"], {"user_id": "u1"})
        with pytest.raises(IntegrityError):
            await db.add_org_member(org["id"], {"user_id": "u1"})

    async def test_update_and_remove_member(self, db: InMemoryDatabase, org: dict) -> None:
        await db.add_org_member(org["id"], {"user_id": "u1"})
        updated = await db.update_org_member(org["id"], "u1", {"role": "admin"})
        assert updated["role"] == "admin"
        assert await db.update_org_member(org["id"], "ghost", {"role": "admin"}) is None
        assert await db.remove_org_member(org["id"], "u1") is True
        assert await db.remove_org_member(org["id"], "u1") is False
        assert await db.get_org_members(org["id"]) == []


class TestInvitations:
    async def test_create_generates_token(self, db: InMemoryDatabase, org: dict) -> None:
        invitation = await db.create_invitation(
            {"org_id": org["id"], "email": "invitee@x.test"}
        )
        assert invitation["id"]
        assert invitation["token"]
        assert invitation["status"] == "pending"

    async def test_invitation_requires_existing_org(self, db: InMemoryDatabase) -> None:
        with pytest.raises(IntegrityError):
            await db.create_invitation({"org_id": "missing", "email": "x@y.test"})

    async def test_get_by_token(self, db: InMemoryDatabase, org: dict) -> None:
        invitation = await db.create_invitation({"org_id": org["id"], "email": "x@y.test"})
        found = await db.get_invitation_by_token(invitation["token"])
        assert found["id"] == invitation["id"]
        assert await db.get_invitation_by_token("bogus") is None

    async def test_pending_filter_and_delete(self, db: InMemoryDatabase, org: dict) -> None:
        first = await db.create_invitation({"org_id": org["id"], "email": "a@y.test"})
        second = await db.create_invitation({"org_id": org["id"], "email": "b@y.test"})
        await db.create_invitation(
            {"org_id": org["id"], "email": "c@y.test", "status": "accepted"}
        )
        pending = await db.get_pending_invitations(org["id"])
        assert {i["id"] for i in pending} == {first["id"], second["id"]}
        assert await db.delete_invitation(first["id"]) is True
        assert await db.delete_invitation(first["id"]) is False
        assert len(await db.get_pending_invitations(org["id"])) == 1
