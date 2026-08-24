"""Tests for the §6 JWT contract: issuance, type enforcement, expiry."""

from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from authy_package.errors import ConfigError, TokenError
from authy_package.utils.security import JWTTokenManager



class TestIssuance:
    def test_access_token_claims(self, jwt_manager: JWTTokenManager) -> None:
        token = jwt_manager.create_access_token("user-123")
        payload = jwt_manager.validate_token(token, expected_type="access")
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"
        assert payload["jti"]
        assert payload["iat"] <= int(time.time()) + 1
        assert payload["exp"] > payload["iat"]
        # iss/aud absent when not configured
        assert "iss" not in payload
        assert "aud" not in payload

    def test_refresh_token_claims(self, jwt_manager: JWTTokenManager) -> None:
        token = jwt_manager.create_refresh_token("user-123")
        payload = jwt_manager.validate_token(token, expected_type="refresh")
        assert payload["type"] == "refresh"
        assert payload["sub"] == "user-123"

    def test_issuer_and_audience_included_when_configured(self, make_config) -> None:
        config = make_config(
            jwt_issuer="https://issuer.authy.test", jwt_audience="authy-api"
        )
        manager = JWTTokenManager(config)
        token = manager.create_access_token("user-1")
        payload = manager.validate_token(token, expected_type="access")
        assert payload["iss"] == "https://issuer.authy.test"
        assert payload["aud"] == "authy-api"

    def test_token_pair_contains_jtis(self, jwt_manager: JWTTokenManager) -> None:
        pair = jwt_manager.create_token_pair("user-42")
        assert set(pair) == {
            "access_token",
            "refresh_token",
            "access_jti",
            "refresh_jti",
        }
        access_payload = jwt_manager.validate_token(
            pair["access_token"], expected_type="access"
        )
        refresh_payload = jwt_manager.validate_token(
            pair["refresh_token"], expected_type="refresh"
        )
        assert access_payload["jti"] == pair["access_jti"]
        assert refresh_payload["jti"] == pair["refresh_jti"]
        assert pair["access_jti"] != pair["refresh_jti"]

    def test_additional_claims_allowed(self, jwt_manager: JWTTokenManager) -> None:
        token = jwt_manager.create_access_token(
            "user-1", additional_claims={"role": "admin", "org_id": "o1"}
        )
        payload = jwt_manager.validate_token(token, expected_type="access")
        assert payload["role"] == "admin"
        assert payload["org_id"] == "o1"

    def test_reserved_claims_rejected(self, jwt_manager: JWTTokenManager) -> None:
        with pytest.raises(ValueError, match="reserved"):
            jwt_manager.create_access_token(
                "user-1", additional_claims={"type": "refresh"}
            )

    def test_empty_subject_rejected(self, jwt_manager: JWTTokenManager) -> None:
        with pytest.raises(ValueError):
            jwt_manager.create_access_token("")


class TestValidation:
    def test_wrong_type_rejected(self, jwt_manager: JWTTokenManager) -> None:
        refresh = jwt_manager.create_refresh_token("user-1")
        with pytest.raises(TokenError) as excinfo:
            jwt_manager.validate_token(refresh, expected_type="access")
        assert excinfo.value.code == "token_wrong_type"

        access = jwt_manager.create_access_token("user-1")
        with pytest.raises(TokenError) as excinfo:
            jwt_manager.validate_token(access, expected_type="refresh")
        assert excinfo.value.code == "token_wrong_type"

    def test_expired_token_rejected(self, make_config) -> None:
        config = make_config(access_token_ttl_seconds=-10, jwt_clock_skew_seconds=0)
        manager = JWTTokenManager(config)
        token = manager.create_access_token("user-1")
        with pytest.raises(TokenError) as excinfo:
            manager.validate_token(token, expected_type="access")
        assert excinfo.value.code == "token_expired"

    def test_clock_skew_leeway_honored(self, make_config) -> None:
        # Expired 5s ago but within the 30s leeway -> still valid.
        config = make_config(access_token_ttl_seconds=-5, jwt_clock_skew_seconds=30)
        manager = JWTTokenManager(config)
        token = manager.create_access_token("user-1")
        payload = manager.validate_token(token, expected_type="access")
        assert payload["sub"] == "user-1"

    def test_tampered_token_rejected(self, jwt_manager: JWTTokenManager) -> None:
        token = jwt_manager.create_access_token("user-1")
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with pytest.raises(TokenError) as excinfo:
            jwt_manager.validate_token(tampered, expected_type="access")
        assert excinfo.value.code == "token_invalid"

    def test_wrong_secret_rejected(self, make_config, jwt_manager: JWTTokenManager) -> None:
        forger = JWTTokenManager(make_config())  # different random secret
        forged = forger.create_access_token("attacker")
        with pytest.raises(TokenError):
            jwt_manager.validate_token(forged, expected_type="access")

    def test_token_missing_required_claims_rejected(self, make_config) -> None:
        config = make_config()
        manager = JWTTokenManager(config)
        # Hand-rolled token without jti/type.
        raw = pyjwt.encode(
            {"sub": "user-1", "iat": int(time.time()), "exp": int(time.time()) + 60},
            config.jwt_secret,
            algorithm="HS256",
        )
        with pytest.raises(TokenError) as excinfo:
            manager.validate_token(raw, expected_type="access")
        assert excinfo.value.code == "token_invalid"

    def test_unknown_expected_type_is_value_error(
        self, jwt_manager: JWTTokenManager
    ) -> None:
        with pytest.raises(ValueError):
            jwt_manager.validate_token("abc", expected_type="id")

    def test_empty_token_raises_token_error(self, jwt_manager: JWTTokenManager) -> None:
        with pytest.raises(TokenError):
            jwt_manager.validate_token("", expected_type="access")

    def test_none_token_raises_token_error(self, jwt_manager: JWTTokenManager) -> None:
        with pytest.raises(TokenError):
            jwt_manager.validate_token(None, expected_type="access")  # type: ignore[arg-type]


class TestConstruction:
    def test_missing_secret_raises_config_error(self, make_config) -> None:
        with pytest.raises(ConfigError):
            JWTTokenManager(make_config(jwt_secret=None))
