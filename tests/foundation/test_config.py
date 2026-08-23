"""Tests for the §2 AuthConfig contract: from_env + validate()."""

from __future__ import annotations

import pytest

from authy_package.config import (
    PUBLIC_DEFAULT_JWT_SECRET,
    AuthConfig,
    DatabaseConfig,
)
from authy_package.errors import ConfigError



class TestFromEnv:
    def test_defaults_without_env(self) -> None:
        cfg = AuthConfig.from_env()
        assert cfg.env == "development"
        # No hardcoded default secret may survive (§2).
        assert cfg.jwt_secret is None
        assert cfg.jwt_algorithm == "HS256"
        assert cfg.access_token_ttl_seconds == 3600
        assert cfg.refresh_token_ttl_days == 7
        assert cfg.session_expiry_seconds == 86400 * 7
        assert cfg.max_concurrent_sessions == 5
        assert cfg.revoke_sessions_on_password_change is True
        assert cfg.rate_limit_enabled is True
        assert cfg.rate_limit_max_attempts == 5
        assert cfg.rate_limit_window_seconds == 300
        assert cfg.account_lockout_duration_seconds == 900
        assert cfg.password_hash_algorithm == "bcrypt"
        assert cfg.bcrypt_rounds == 12
        assert cfg.reset_token_ttl_seconds == 900
        assert cfg.base_url == "http://localhost:8000"
        assert cfg.magic_link_ttl_seconds == 600
        assert cfg.default_redirect_url is None
        assert cfg.auto_create_users is False
        assert cfg.rp_id is None
        assert cfg.rp_name == "Authy"
        assert cfg.email_provider == "mailjet"

    def test_legacy_authy_env_names_preserved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTHY_ENV", "staging")
        monkeypatch.setenv("AUTHY_JWT_SECRET", "s" * 40)
        monkeypatch.setenv("AUTHY_DB_TYPE", "memory")
        monkeypatch.setenv("AUTHY_DB_NAME", "authy")
        monkeypatch.setenv("AUTHY_TOKEN_EXPIRATION", "1800")
        monkeypatch.setenv("AUTHY_REFRESH_TOKEN_EXPIRATION", "1234")
        monkeypatch.setenv("AUTHY_RATE_LIMIT_ENABLED", "false")
        monkeypatch.setenv("AUTHY_RATE_LIMIT_MAX_ATTEMPTS", "9")
        monkeypatch.setenv("AUTHY_REDIS_URL", "redis://cache:6380")
        monkeypatch.setenv("AUTHY_CACHE_ENABLED", "true")
        monkeypatch.setenv("AUTHY_EMAIL_ENABLED", "true")
        monkeypatch.setenv("MAILJET_API_KEY", "mj-key")
        monkeypatch.setenv("MAILJET_API_SECRET", "mj-secret")
        monkeypatch.setenv("SENDER_EMAIL", "noreply@authy.test")
        monkeypatch.setenv("SENDER_NAME", "Authy NoReply")

        cfg = AuthConfig.from_env()
        assert cfg.env == "staging"
        assert cfg.jwt_secret == "s" * 40
        assert cfg.database.db_type == "memory"
        assert cfg.database.db_name == "authy"
        assert cfg.access_token_ttl_seconds == 1800
        assert cfg.cache.token_expiration == 1800
        assert cfg.cache.refresh_token_expiration == 1234
        assert cfg.rate_limit_enabled is False
        assert cfg.rate_limit_max_attempts == 9
        assert cfg.cache.redis_url == "redis://cache:6380"
        assert cfg.email_enabled is True
        assert cfg.mailjet_api_key == "mj-key"
        assert cfg.mailjet_api_secret == "mj-secret"
        assert cfg.sender_email == "noreply@authy.test"
        assert cfg.sender_name == "Authy NoReply"

    def test_new_canonical_env_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTHY_JWT_ISSUER", "https://issuer.authy.test")
        monkeypatch.setenv("AUTHY_JWT_AUDIENCE", "authy-api")
        monkeypatch.setenv("AUTHY_JWT_CLOCK_SKEW_SECONDS", "45")
        monkeypatch.setenv("AUTHY_SESSION_EXPIRY_SECONDS", "3600")
        monkeypatch.setenv("AUTHY_MAX_CONCURRENT_SESSIONS", "2")
        monkeypatch.setenv("AUTHY_REVOKE_SESSIONS_ON_PASSWORD_CHANGE", "false")
        monkeypatch.setenv("AUTHY_RATE_LIMIT_WINDOW_SECONDS", "60")
        monkeypatch.setenv("AUTHY_ACCOUNT_LOCKOUT_DURATION_SECONDS", "120")
        monkeypatch.setenv("AUTHY_MFA_REQUIRED", "true")
        monkeypatch.setenv("AUTHY_PASSWORD_HASH_ALGORITHM", "argon2")
        monkeypatch.setenv("AUTHY_BCRYPT_ROUNDS", "10")
        monkeypatch.setenv("AUTHY_RESET_TOKEN_TTL_SECONDS", "300")
        monkeypatch.setenv("AUTHY_BASE_URL", "https://auth.authy.test")
        monkeypatch.setenv("AUTHY_MAGIC_LINK_TTL_SECONDS", "120")
        monkeypatch.setenv("AUTHY_DEFAULT_REDIRECT_URL", "https://auth.authy.test/home")
        monkeypatch.setenv("AUTHY_AUTO_CREATE_USERS", "true")
        monkeypatch.setenv("AUTHY_RP_ID", "authy.test")
        monkeypatch.setenv("AUTHY_RP_NAME", "Authy Test")
        monkeypatch.setenv("AUTHY_REFRESH_TOKEN_TTL_DAYS", "14")

        cfg = AuthConfig.from_env()
        assert cfg.jwt_issuer == "https://issuer.authy.test"
        assert cfg.jwt_audience == "authy-api"
        assert cfg.jwt_clock_skew_seconds == 45
        assert cfg.session_expiry_seconds == 3600
        assert cfg.max_concurrent_sessions == 2
        assert cfg.revoke_sessions_on_password_change is False
        assert cfg.rate_limit_window_seconds == 60
        assert cfg.account_lockout_duration_seconds == 120
        assert cfg.mfa_required is True
        assert cfg.password_hash_algorithm == "argon2"
        assert cfg.bcrypt_rounds == 10
        assert cfg.reset_token_ttl_seconds == 300
        assert cfg.base_url == "https://auth.authy.test"
        assert cfg.magic_link_ttl_seconds == 120
        assert cfg.default_redirect_url == "https://auth.authy.test/home"
        assert cfg.auto_create_users is True
        assert cfg.rp_id == "authy.test"
        assert cfg.rp_name == "Authy Test"
        assert cfg.refresh_token_ttl_days == 14
        assert cfg.refresh_token_ttl_seconds == 14 * 86400

    def test_malformed_int_env_raises_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTHY_TOKEN_EXPIRATION", "not-a-number")
        with pytest.raises(ConfigError):
            AuthConfig.from_env()


class TestValidate:
    def test_valid_config_returns_true(self, make_config) -> None:
        assert make_config().validate() is True

    def test_missing_jwt_secret_fails(self, make_config) -> None:
        cfg = make_config(jwt_secret=None)
        with pytest.raises(ConfigError, match="jwt_secret"):
            cfg.validate()

    def test_empty_jwt_secret_fails(self, make_config) -> None:
        cfg = make_config(jwt_secret="")
        with pytest.raises(ConfigError, match="jwt_secret"):
            cfg.validate()

    def test_public_default_secret_rejected(self, make_config) -> None:
        cfg = make_config(jwt_secret=PUBLIC_DEFAULT_JWT_SECRET)
        with pytest.raises(ConfigError, match="public default"):
            cfg.validate()

    def test_placeholder_secret_rejected(self, make_config) -> None:
        cfg = make_config(jwt_secret="changeme-please")
        with pytest.raises(ConfigError, match="jwt_secret"):
            cfg.validate()

    def test_missing_database_url_fails(self, make_config) -> None:
        cfg = make_config(
            database=DatabaseConfig(db_type="sql", connection_string="")
        )
        with pytest.raises(ConfigError, match="connection_string"):
            cfg.validate()

    def test_memory_db_needs_no_url(self, make_config) -> None:
        cfg = make_config(database=DatabaseConfig(db_type="memory"))
        assert cfg.validate() is True

    def test_unknown_db_type_fails(self, make_config) -> None:
        cfg = make_config(database=DatabaseConfig(db_type="neo4j"))
        with pytest.raises(ConfigError, match="db_type"):
            cfg.validate()

    def test_invalid_env_fails(self, make_config) -> None:
        cfg = make_config(env="qa")
        with pytest.raises(ConfigError, match="env"):
            cfg.validate()

    def test_invalid_hash_algorithm_fails(self, make_config) -> None:
        cfg = make_config(password_hash_algorithm="md5")
        with pytest.raises(ConfigError, match="password_hash_algorithm"):
            cfg.validate()

    def test_non_positive_ttl_fails(self, make_config) -> None:
        cfg = make_config(reset_token_ttl_seconds=0)
        with pytest.raises(ConfigError, match="reset_token_ttl_seconds"):
            cfg.validate()

    def test_bcrypt_rounds_bounds(self, make_config) -> None:
        assert make_config(bcrypt_rounds=4).validate() is True
        assert make_config(bcrypt_rounds=31).validate() is True
        with pytest.raises(ConfigError, match="bcrypt_rounds"):
            make_config(bcrypt_rounds=3).validate()

    def test_production_http_base_url_rejected(self, make_config) -> None:
        cfg = make_config(env="production", base_url="http://auth.authy.test")
        with pytest.raises(ConfigError, match="https"):
            cfg.validate()

    def test_production_example_url_rejected(self, make_config) -> None:
        cfg = make_config(env="production", base_url="https://auth.example.com")
        with pytest.raises(ConfigError, match="example.com"):
            cfg.validate()

    def test_production_placeholder_mailjet_key_rejected(self, make_config) -> None:
        cfg = make_config(
            env="production",
            base_url="https://auth.authy.test",
            mailjet_api_key="placeholder-key",
        )
        with pytest.raises(ConfigError, match="mailjet_api_key"):
            cfg.validate()

    def test_production_sender_example_com_rejected(self, make_config) -> None:
        cfg = make_config(
            env="production",
            base_url="https://auth.authy.test",
            sender_email="noreply@example.com",
        )
        with pytest.raises(ConfigError, match="sender_email"):
            cfg.validate()

    def test_valid_production_config_passes(self, make_config) -> None:
        cfg = make_config(
            env="production",
            base_url="https://auth.authy.test",
            mailjet_api_key="real-key-value",
            mailjet_api_secret="real-secret-value",
            sender_email="noreply@authy.test",
        )
        assert cfg.validate() is True
