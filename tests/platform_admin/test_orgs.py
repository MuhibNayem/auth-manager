"""Organization flows: create, members, invitations (expiry + single-use)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from authy_package.organizations.org_manager import PLAN_MAX_MEMBERS


@pytest.mark.asyncio
async def test_create_org_adds_owner_and_enforces_slug_fallback(orgs, admin_user):
    org = await orgs.create_organization("Acme Corp", admin_user["id"], plan="free")
    assert org["slug"] == "acme-corp"
    assert org["max_members"] == PLAN_MAX_MEMBERS["free"]
    members = await orgs.get_members(org["id"])
    assert members[0]["user_id"] == admin_user["id"]
    assert members[0]["role"] == "owner"

    # Same name again → slug uniqueness fallback suffix.
    second = await orgs.create_organization("Acme Corp", admin_user["id"])
    assert second["slug"].startswith("acme-corp-")
    assert second["slug"] != org["slug"]


@pytest.mark.asyncio
async def test_add_member_enforces_plan_cap(orgs, db, admin_user):
    org = await orgs.create_organization("Tiny Co", admin_user["id"], plan="free")
    limit = org["max_members"]
    for index in range(limit - 1):
        user = await db.create_user({"email": f"m{index}@example.com"})
        await orgs.add_member(org["id"], user["id"], added_by=admin_user["id"])
    overflow = await db.create_user({"email": "overflow@example.com"})
    with pytest.raises(ValueError):
        await orgs.add_member(org["id"], overflow["id"])


@pytest.mark.asyncio
async def test_last_owner_protection(orgs, db, admin_user):
    org = await orgs.create_organization("Ownerly", admin_user["id"])
    with pytest.raises(PermissionError):
        await orgs.remove_member(org["id"], admin_user["id"])
    with pytest.raises(PermissionError):
        await orgs.update_member_role(org["id"], admin_user["id"], "member")


@pytest.mark.asyncio
async def test_invitation_flow_without_email_service(orgs, db, admin_user):
    """email_service=None → invitation still created with token (logged)."""
    org = await orgs.create_organization("Inviters", admin_user["id"])
    invitee = await db.create_user({"email": "invitee@example.com"})

    invitation = await orgs.send_invitation(
        org["id"], "invitee@example.com", invited_by=admin_user["id"]
    )
    assert invitation["token"]
    assert invitation["status"] == "pending"

    # Duplicate pending invitation for the same email is rejected.
    from authy_package.errors import IntegrityError

    with pytest.raises(IntegrityError):
        await orgs.send_invitation(
            org["id"], "invitee@example.com", invited_by=admin_user["id"]
        )

    member = await orgs.accept_invitation(invitation["token"], invitee["id"])
    assert member["user_id"] == invitee["id"]
    assert member["role"] == "member"

    # Single-use: second accept must fail.
    from authy_package.errors import NotFoundError

    with pytest.raises(NotFoundError):
        await orgs.accept_invitation(invitation["token"], invitee["id"])


@pytest.mark.asyncio
async def test_expired_invitation_cannot_be_accepted(orgs, db, admin_user):
    org = await orgs.create_organization("Expiry Inc", admin_user["id"])
    invitee = await db.create_user({"email": "late@example.com"})
    invitation = await orgs.send_invitation(
        org["id"], "late@example.com", invited_by=admin_user["id"]
    )
    # Force expiry directly on the stored record.
    await db.delete_invitation(invitation["id"])
    from authy_package.organizations.org_manager import InvitationStatus

    invitation["expires_at"] = invitation["expires_at"] - timedelta(hours=200)
    invitation["status"] = InvitationStatus.PENDING.value
    await db.create_invitation(invitation)

    from authy_package.errors import NotFoundError

    with pytest.raises(NotFoundError):
        await orgs.accept_invitation(invitation["token"], invitee["id"])


@pytest.mark.asyncio
async def test_get_organizations_paginated_totals(orgs, admin_user):
    for index in range(3):
        await orgs.create_organization(f"Pagina {index}", admin_user["id"])
    rows, total = await orgs.get_organizations_paginated(page=1, page_size=2)
    assert total == 3
    assert len(rows) == 2
    rows2, total2 = await orgs.get_organizations_paginated(page=2, page_size=2)
    assert total2 == 3
    assert len(rows2) == 1


@pytest.mark.asyncio
async def test_org_routes_via_api(client, admin_headers, admin_user):
    created = await client.post(
        "/admin/api/v1/organizations",
        headers=admin_headers,
        json={"name": "API Org", "plan": "pro"},
    )
    assert created.status_code == 201, created.text
    org = created.json()
    assert org["plan"] == "pro"

    listed = await client.get("/admin/api/v1/organizations", headers=admin_headers)
    assert listed.status_code == 200
    assert listed.json()["pagination"]["total"] == 1

    detail = await client.get(
        f"/admin/api/v1/organizations/{org['id']}", headers=admin_headers
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["members"][0]["user_id"] == admin_user["id"]

    invitation = await client.post(
        f"/admin/api/v1/organizations/{org['id']}/invitations",
        headers=admin_headers,
        json={"email": "newbie@example.com", "role": "member"},
    )
    assert invitation.status_code == 201
    assert invitation.json()["token"]
