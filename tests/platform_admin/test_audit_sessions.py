"""Audit log API tests: search, CSV QUOTE_ALL with malicious strings, sessions."""

from __future__ import annotations

import csv
import io

import pytest

from authy_package.admin.audit_logger import EventType


@pytest.mark.asyncio
async def test_audit_csv_export_quotes_all_fields_including_malicious(
    client, admin_headers, db
):
    malicious = (
        '","injection\n=1+2,cmd|"/C calc"!@#\r\n'
        '"evil" "quotes",,,\x00not-really'
    )
    await db.save_audit_event(
        {
            "event_type": EventType.ADMIN_ACTION.value,
            "actor": "attacker",
            "target": "t-1",
            "action": malicious,
            "ip_address": "203.0.113.5",
        }
    )

    response = await client.get(
        "/admin/api/v1/audit-logs/export",
        headers=admin_headers,
        params={"format": "csv"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    text = response.text

    # Every field is quoted (QUOTE_ALL): header row included.
    first_line = text.splitlines()[0]
    assert first_line.startswith('"id","timestamp"')

    # Parse back with the csv reader: the malicious action survives intact
    # as ONE cell, proving the quoting neutralizes delimiter injection.
    reader = csv.DictReader(io.StringIO(text))
    rows = [row for row in reader if row["actor"] == "attacker"]
    assert len(rows) == 1
    assert rows[0]["action"] == malicious

    # Raw newlines from the payload must never break the row structure:
    # the row containing them is fully enclosed in quotes.
    assert '"' + malicious.replace('"', '""') + '"' in text


@pytest.mark.asyncio
async def test_audit_search_by_actor_and_type_via_api(client, admin_headers, db):
    await db.save_audit_event(
        {"event_type": EventType.LOGIN_SUCCESS.value, "actor": "u-9", "action": "ok"}
    )
    await db.save_audit_event(
        {"event_type": EventType.LOGIN_FAILED.value, "actor": "u-9", "action": "bad"}
    )
    response = await client.get(
        "/admin/api/v1/audit-logs",
        headers=admin_headers,
        params={"actor": "u-9", "event_types": "auth.login.success"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["pagination"]["total"] == 1
    assert body["events"][0]["event_type"] == "auth.login.success"


@pytest.mark.asyncio
async def test_session_listing_and_revocation(client, admin_headers, admin_user):
    # admin_headers logged in once → one active session exists.
    listed = await client.get(
        "/admin/api/v1/sessions",
        headers=admin_headers,
        params={"user_id": admin_user["id"]},
    )
    assert listed.status_code == 200
    sessions = listed.json()["sessions"]
    assert len(sessions) >= 1
    session_id = sessions[0]["id"]

    revoked = await client.delete(
        f"/admin/api/v1/sessions/{session_id}", headers=admin_headers
    )
    assert revoked.status_code == 200

    # Revoking twice → 404 (no longer active).
    again = await client.delete(
        f"/admin/api/v1/sessions/{session_id}", headers=admin_headers
    )
    assert again.status_code == 404

    revoke_all = await client.post(
        f"/admin/api/v1/sessions/user/{admin_user['id']}/revoke-all",
        headers=admin_headers,
    )
    assert revoke_all.status_code == 200
    assert revoke_all.json()["revoked"] >= 0


@pytest.mark.asyncio
async def test_audit_logger_queue_flushes_on_close(db):
    """Queued (non-sync) events are persisted by close()."""
    from authy_package.admin.audit_logger import AuditLogger

    audit = AuditLogger(db, flush_interval_seconds=60)
    await audit.log(EventType.LOGOUT, "User logged out", actor_id="u-1")
    events, total = await db.search_audit_events()
    assert total == 0  # still queued
    await audit.close()
    events, total = await db.search_audit_events()
    assert total == 1
    assert events[0]["event_type"] == "auth.logout"
