"""Package __init__ tests: lazy exports, version, validated get_auth."""

from __future__ import annotations

import pytest

import authy_package
from authy_package import AuthConfig
from authy_package.config import DatabaseConfig
from authy_package.errors import ConfigError


def test_version_is_2_0_0():
    assert authy_package.__version__ == "2.0.0"


def test_all_exports_resolve():
    """__all__ must not list names whose import failed."""
    missing = [name for name in authy_package.__all__ if not hasattr(authy_package, name)]
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
        assert getattr(authy_package, flag) is True, flag


def test_key_exports_are_usable():
    assert authy_package.AuthManager is authy_package.TraditionalAuthManager
    assert authy_package.SessionManager is not None
    assert authy_package.MagicLinkManager is not None
    assert authy_package.PasskeyManager is not None
    assert authy_package.MFAAuthManager is not None
    assert authy_package.SAMLManager is not None
    assert authy_package.OIDCManager is not None
    assert authy_package.build_security_report is not None
    assert authy_package.verify_and_upgrade_legacy_hash is not None


def test_get_auth_validates_config_missing_secret(monkeypatch):
    monkeypatch.setattr(authy_package, "_auth_instance", None)
    bad = AuthConfig(database=DatabaseConfig(db_type="memory"))
    with pytest.raises(ConfigError):
        authy_package.get_auth(bad)


def test_init_auth_returns_manager_and_get_auth_reuses(monkeypatch):
    monkeypatch.setattr(authy_package, "_auth_instance", None)
    import secrets

    config = AuthConfig(
        jwt_secret=secrets.token_urlsafe(32),
        database=DatabaseConfig(db_type="memory"),
        base_url="http://localhost:8000",
    )
    instance = authy_package.init_auth(config)
    assert isinstance(instance, authy_package.TraditionalAuthManager)
    assert authy_package.get_auth() is instance


def test_unknown_attribute_raises_attribute_error():
    with pytest.raises(AttributeError):
        authy_package.definitely_not_an_export
