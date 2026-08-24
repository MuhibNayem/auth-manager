"""Compliance tests: report function, GDPR redaction, audit chain."""

from __future__ import annotations

import pytest

from tessera.compliance import (
    GDPRComplianceEngine,
    SOC2AuditLogger,
    build_security_report,
    redact_sensitive,
    verify_audit_chain,
)


@pytest.fixture
async def populated_db(db):
    await db.create_user(
        {
            "email": "gdpr@example.com",
            "username": "gdpr",
            "hashed_password": "secret-hash",
            "mfa_secret": "totp-secret",
            "access_token": "live-token",
        }
    )
    for event_type in ("login_failed", "login_failed", "user.login", "suspicious_activity"):
        await db.save_audit_event(
            {"event_type": event_type, "actor": "gdpr@example.com", "target": "gdpr@example.com"}
        )
    return db


async def test_build_security_report_is_pure_dict(populated_db):
    report = await build_security_report(populated_db)
    assert isinstance(report, dict)
    assert report["users"]["total"] >= 1
    assert report["audit"]["chain_intact"] is True
    assert report["threats"]["failed_login_attempts"] == 2
    assert report["threats"]["suspicious_activities"] == 1
    assert report["threats"]["threat_level"] in ("low", "medium", "high", "critical")
    assert "generated_at" in report


async def test_build_security_report_requires_db():
    with pytest.raises(ValueError):
        await build_security_report(None)


async def test_verify_audit_chain_detects_tampering(populated_db):
    assert await verify_audit_chain(populated_db) is True
    # Tamper with the first event's payload.
    populated_db._audit_chain[0]["actor"] = "tampered"
    assert await verify_audit_chain(populated_db) is False


def test_redact_sensitive_covers_token_secret_password():
    data = {
        "email": "keep@me.com",
        "access_token": "t",
        "refresh_token": "t",
        "client_secret": "s",
        "hashed_password": "p",
        "nested": {"api_secret_key": "s", "name": "keep"},
        "list": [{"password": "p"}, {"ok": 1}],
    }
    redacted = redact_sensitive(data)
    assert redacted["email"] == "keep@me.com"
    assert redacted["access_token"] == "[REDACTED]"
    assert redacted["refresh_token"] == "[REDACTED]"
    assert redacted["client_secret"] == "[REDACTED]"
    assert redacted["hashed_password"] == "[REDACTED]"
    assert redacted["nested"]["api_secret_key"] == "[REDACTED]"
    assert redacted["nested"]["name"] == "keep"
    assert redacted["list"][0]["password"] == "[REDACTED]"
    assert redacted["list"][1]["ok"] == 1


async def test_gdpr_export_redacts_sensitive(populated_db):
    engine = GDPRComplianceEngine(populated_db)
    user = await populated_db.get_user_by_identifier(email="gdpr@example.com")
    export = await engine.export_user_data(user["id"])
    assert export["user"]["hashed_password"] == "[REDACTED]"
    assert export["user"]["mfa_secret"] == "[REDACTED]"
    assert export["user"]["access_token"] == "[REDACTED]"
    assert export["user"]["email"] == "gdpr@example.com"
    assert export["audit_logs"]  # audit events included


async def test_gdpr_export_unknown_user_raises(populated_db):
    engine = GDPRComplianceEngine(populated_db)
    with pytest.raises(ValueError):
        await engine.export_user_data("does-not-exist")


async def test_gdpr_soft_delete_anonymizes(populated_db):
    engine = GDPRComplianceEngine(populated_db)
    user = await populated_db.get_user_by_identifier(email="gdpr@example.com")
    result = await engine.delete_user_data(user["id"], hard_delete=False)
    assert result["anonymized"] is True

    updated = await populated_db.get_user_by_id(user["id"])
    assert updated["email"].endswith("@anonymized.invalid")
    assert updated["hashed_password"] is None
    assert updated["mfa_secret"] is None
    assert updated["is_active"] is False


async def test_gdpr_hard_delete_removes_user(populated_db):
    engine = GDPRComplianceEngine(populated_db)
    user = await populated_db.get_user_by_identifier(email="gdpr@example.com")
    result = await engine.delete_user_data(user["id"], hard_delete=True)
    assert result["deleted"] is True
    assert await populated_db.get_user_by_id(user["id"]) is None


async def test_soc2_audit_logger_delegates_checksum_to_db(populated_db):
    logger = SOC2AuditLogger(populated_db)
    event = await logger.log_event({"event_type": "custom.event", "actor": "x"})
    assert event is not None
    assert event.get("checksum")  # computed by the db adapter
    assert await logger.verify_log_integrity() is True
