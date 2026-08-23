"""Admin v2 tests: API keys, settings, bulk v2, analytics, RBAC."""

from __future__ import annotations

from datetime import timedelta, timezone, datetime

import pytest

from authy_package.admin.audit_logger import EventType


@pytest.mark.asyncio
async def test_api_key_create_once_validate_revoke(client, admin_headers):
    created = await client.post(
        "/admin/v2/api-keys",
        headers=admin_headers,
        json={"name": "ci-key", "scopes": ["admin:*"]},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    api_key = body["api_key"]
    assert api_key.startswith("authy_ak_")
    key_id = body["id"]

    # Plaintext is never listed again; hashes never exposed.
    listed = await client.get("/admin/v2/api-keys", headers=admin_headers)
    records = listed.json()["api_keys"]
    assert all("api_key" not in record and "key_hash" not in record for record in records)
    assert any(record["id"] == key_id for record in records)

    # The key authenticates a /admin/v2 request.
    via_key = await client.get(
        "/admin/v2/api-keys", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert via_key.status_code == 200

    # Revoke → the same key now gets 401.
    revoked = await client.delete(f"/admin/v2/api-keys/{key_id}", headers=admin_headers)
    assert revoked.status_code == 200
    after_revoke = await client.get(
        "/admin/v2/api-keys", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert after_revoke.status_code == 401


@pytest.mark.asyncio
async def test_api_key_scope_enforcement(client, admin_headers, db):
    created = await client.post(
        "/admin/v2/api-keys",
        headers=admin_headers,
        json={"name": "audit-only", "scopes": ["audit:logs"]},
    )
    api_key = created.json()["api_key"]
    headers = {"Authorization": f"Bearer {api_key}"}

    allowed = await client.post(
        "/admin/v2/audit-logs/search", headers=headers, json={}
    )
    assert allowed.status_code == 200

    forbidden = await client.post(
        "/admin/v2/users/bulk-action",
        headers=headers,
        json={"user_ids": ["x"], "action": "enable"},
    )
    assert forbidden.status_code == 403


@pytest.mark.asyncio
async def test_branding_and_localization_persisted(client, admin_headers, db):
    updated = await client.put(
        "/admin/v2/config/branding",
        headers=admin_headers,
        json={"app_name": "MyBrand", "primary_color": "#ff0000"},
    )
    assert updated.status_code == 200
    assert updated.json()["app_name"] == "MyBrand"

    fetched = await client.get("/admin/v2/config/branding", headers=admin_headers)
    assert fetched.json()["app_name"] == "MyBrand"
    assert (await db.get_setting("admin:branding"))["app_name"] == "MyBrand"

    localized = await client.put(
        "/admin/v2/config/localization",
        headers=admin_headers,
        json={"default_locale": "es-ES", "supported_locales": ["es-ES", "en-US"]},
    )
    assert localized.status_code == 200
    again = await client.get("/admin/v2/config/localization", headers=admin_headers)
    assert again.json()["default_locale"] == "es-ES"


@pytest.mark.asyncio
async def test_reports_generate_real_csv_and_download(client, admin_headers, db):
    report = await client.post(
        "/admin/v2/reports/generate",
        headers=admin_headers,
        json={"report_type": "users", "format": "csv"},
    )
    assert report.status_code == 200, report.text
    job = report.json()
    assert len(job["job_id"]) == 16  # secrets.token_hex(8)
    assert job["status"] == "completed"

    download = await client.get(
        f"/admin/v2/reports/{job['job_id']}/download", headers=admin_headers
    )
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")
    content = download.text
    assert '"email"' in content  # QUOTE_ALL header
    assert "admin@example.com" in content  # real data from the db

    missing = await client.get("/admin/v2/reports/deadbeef/download", headers=admin_headers)
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_v2_bulk_action_real_and_audited(client, admin_headers, db):
    user = await db.create_user({"email": "v2bulk@example.com"})
    response = await client.post(
        "/admin/v2/users/bulk-action",
        headers=admin_headers,
        json={"user_ids": [user["id"]], "action": "disable"},
    )
    assert response.status_code == 200
    assert response.json()["processed_count"] == 1
    stored = await db.get_user_by_id(user["id"])
    assert stored["is_active"] is False

    events, total = await db.search_audit_events(event_types=["admin.action"])
    assert total == 1

    too_big = await client.post(
        "/admin/v2/users/bulk-action",
        headers=admin_headers,
        json={"user_ids": [f"u{i}" for i in range(1001)], "action": "enable"},
    )
    assert too_big.status_code == 422


@pytest.mark.asyncio
async def test_security_analytics_rule_based_detectors(client, admin_headers, db):
    now = datetime.now(timezone.utc)
    # Seed 6 failed logins from one IP (brute force) and a rapid IP change
    # for one actor (impossible-travel proxy).
    events = []
    for index in range(6):
        events.append(
            {
                "event_type": EventType.LOGIN_FAILED.value,
                "actor": "victim",
                "target": "victim",
                "action": "failed",
                "ip_address": "203.0.113.9",
                "metadata": {"identifier": "victim"},
                "timestamp": now - timedelta(minutes=index),
            }
        )
    events.append(
        {
            "event_type": EventType.LOGIN_SUCCESS.value,
            "actor": "traveler",
            "action": "ok",
            "ip_address": "198.51.100.1",
            "timestamp": now - timedelta(minutes=20),
        }
    )
    events.append(
        {
            "event_type": EventType.LOGIN_SUCCESS.value,
            "actor": "traveler",
            "action": "ok",
            "ip_address": "203.0.113.77",
            "timestamp": now - timedelta(minutes=10),
        }
    )
    await db.save_audit_events(events)

    response = await client.get(
        "/admin/v2/security/analytics", headers=admin_headers, params={"window_hours": 24}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["heuristic"] is True
    types = {incident["type"] for incident in body["incidents"]}
    assert "brute_force" in types
    assert "impossible_travel_proxy" in types


@pytest.mark.asyncio
async def test_advanced_audit_search_compiles_filters(client, admin_headers, db):
    await db.save_audit_event(
        {
            "event_type": EventType.USER_CREATED.value,
            "actor": "admin-1",
            "target": "u-1",
            "action": "created",
        }
    )
    response = await client.post(
        "/admin/v2/audit-logs/search",
        headers=admin_headers,
        json={"event_types": [EventType.USER_CREATED.value], "actor": "admin-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["events"][0]["target"] == "u-1"
