"""User CRUD, pagination totals, bounded bulk ops and impersonation."""

from __future__ import annotations

import pytest


async def _create_user(client, headers, email: str, role: str = "user"):
    response = await client.post(
        "/admin/api/v1/users",
        headers=headers,
        json={
            "username": email.split("@")[0],
            "email": email,
            "password": "Sup3rSecret!x",
            "role": role,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_user_crud_roundtrip(client, admin_headers):
    created = await _create_user(client, admin_headers, "alice@example.com")
    user_id = created["id"]
    assert "hashed_password" not in created

    fetched = await client.get(f"/admin/api/v1/users/{user_id}", headers=admin_headers)
    assert fetched.status_code == 200
    assert fetched.json()["email"] == "alice@example.com"

    updated = await client.put(
        f"/admin/api/v1/users/{user_id}",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["is_active"] is False

    deleted = await client.delete(f"/admin/api/v1/users/{user_id}", headers=admin_headers)
    assert deleted.status_code == 200

    missing = await client.get(f"/admin/api/v1/users/{user_id}", headers=admin_headers)
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_email_conflict_returns_409(client, admin_headers):
    await _create_user(client, admin_headers, "dupe@example.com")
    second = await client.post(
        "/admin/api/v1/users",
        headers=admin_headers,
        json={"email": "dupe@example.com", "password": "Sup3rSecret!x"},
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_list_users_pagination_totals(client, admin_headers):
    for index in range(5):
        await _create_user(client, admin_headers, f"paged{index}@example.com")
    response = await client.get(
        "/admin/api/v1/users",
        headers=admin_headers,
        params={"page": 1, "page_size": 2, "search": "paged"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total"] == 5
    assert data["pagination"]["total_pages"] == 3
    assert len(data["users"]) == 2


@pytest.mark.asyncio
async def test_bulk_operation_above_1000_rejected_with_422(client, admin_headers):
    response = await client.post(
        "/admin/api/v1/users/bulk",
        headers=admin_headers,
        json={"user_ids": [f"user-{i}" for i in range(1001)], "action": "deactivate"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_bulk_operation_applies_and_audits(client, admin_headers, db):
    user = await _create_user(client, admin_headers, "bulkme@example.com")
    response = await client.post(
        "/admin/api/v1/users/bulk",
        headers=admin_headers,
        json={"user_ids": [user["id"]], "action": "deactivate", "reason": "test"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["succeeded"] == [user["id"]]
    stored = await db.get_user_by_id(user["id"])
    assert stored["is_active"] is False

    events, total = await db.search_audit_events(event_types=["admin.action"])
    assert total == 1
    assert events[0]["target"] == user["id"]


@pytest.mark.asyncio
async def test_impersonation_refuses_privileged_targets(client, admin_headers, admin_user):
    response = await client.post(
        f"/admin/api/v1/users/{admin_user['id']}/impersonate",
        headers=admin_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_impersonation_issues_short_lived_token(
    client, admin_headers, token_manager
):
    target = await _create_user(client, admin_headers, "victim@example.com")
    response = await client.post(
        f"/admin/api/v1/users/{target['id']}/impersonate",
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expires_in"] == 900
    # The issued token validates as an access token for the target user.
    payload = token_manager.validate_token(body["access_token"], expected_type="access")
    assert payload["sub"] == target["id"]
    assert payload["impersonation"] is True
