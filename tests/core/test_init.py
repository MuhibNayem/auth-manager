"""Package __init__ tests: lazy exports, version, validated get_auth."""

from __future__ import annotations

import pytest

import tessera
from tessera import AuthConfig
from tessera.config import DatabaseConfig
from tessera.errors import ConfigError


def test_version_is_2_0_0():
    assert tessera.__version__ == "2.0.0"


def test_all_exports_resolve():
    """__all__ must not list names whose import failed."""
    missing = [name for name in tessera.__all__ if not hasattr(tessera, name)]
    assert missing == []


def test_core_availability_flags_are_true():
    for flag in (
        "CORE_AVAILABLE",
        "SESSIONS_AVAILABLE",
        "MFA_AVAILABLE",
        "PASSWORDLESS_AVAILABLE",
        "PASSWORD_SECURITY_AVAILABLE",
        "SAML_AVAILABLE",
        "OIDC_AVAILABLE",
        "SOCIAL_AVAILABLE",
        "MIGRATION_AVAILABLE",
        "COMPLIANCE_AVAILABLE",
    ):
        assert getattr(tessera, flag) is True, flag


def test_key_exports_are_usable():
    assert tessera.AuthManager is tessera.TraditionalAuthManager
    assert tessera.SessionManager is not None
    assert tessera.MagicLinkManager is not None
    assert tessera.PasskeyManager is not None
    assert tessera.MFAAuthManager is not None
    assert tessera.SAMLManager is not None
    assert tessera.OIDCManager is not None
    assert tessera.build_security_report is not None
    assert tessera.verify_and_upgrade_legacy_hash is not None


def test_get_auth_validates_config_missing_secret(monkeypatch):
    monkeypatch.setattr(tessera, "_auth_instance", None)
    bad = AuthConfig(database=DatabaseConfig(db_type="memory"))
    with pytest.raises(ConfigError):
        tessera.get_auth(bad)


def test_init_auth_returns_manager_and_get_auth_reuses(monkeypatch):
    monkeypatch.setattr(tessera, "_auth_instance", None)
    import secrets

    config = AuthConfig(
        jwt_secret=secrets.token_urlsafe(32),
        database=DatabaseConfig(db_type="memory"),
        base_url="http://localhost:8000",
    )
    instance = tessera.init_auth(config)
    assert isinstance(instance, tessera.TraditionalAuthManager)
    assert tessera.get_auth() is instance


def test_unknown_attribute_raises_attribute_error():
    with pytest.raises(AttributeError):
        tessera.definitely_not_an_export
