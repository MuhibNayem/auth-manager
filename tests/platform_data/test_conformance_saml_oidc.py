"""Conformance: SAML replay ledgers (atomic consumes) and OIDC providers."""

from __future__ import annotations

import asyncio
import time

import pytest

from authy_package.db.abstract_db import AbstractDatabase
from authy_package.errors import IntegrityError


class TestSaml:
    async def test_request_save_consume_single_use(
        self, db: AbstractDatabase
    ) -> None:
        await db.save_saml_request("req-1", {"relay_state": "/dash"}, ttl_seconds=60)
        data = await db.consume_saml_request("req-1")
        assert data == {"relay_state": "/dash"}
        assert await db.consume_saml_request("req-1") is None

    async def test_concurrent_consume_single_winner(
        self, db: AbstractDatabase
    ) -> None:
        await db.save_saml_request("req-2", {"x": 1}, ttl_seconds=60)
        results = await asyncio.gather(
            db.consume_saml_request("req-2"),
            db.consume_saml_request("req-2"),
            db.consume_saml_request("req-2"),
        )
        winners = [r for r in results if r is not None]
        assert len(winners) == 1
        assert winners[0] == {"x": 1}

    async def test_expired_request_returns_none(self, db: AbstractDatabase) -> None:
        await db.save_saml_request("req-3", {"x": 1}, ttl_seconds=1)
        time.sleep(1.1)
        assert await db.consume_saml_request("req-3") is None

    async def test_ttl_validation(self, db: AbstractDatabase) -> None:
        with pytest.raises(ValueError):
            await db.save_saml_request("req", {}, ttl_seconds=0)
        with pytest.raises(ValueError):
            await db.save_saml_request("", {}, ttl_seconds=10)
        with pytest.raises(ValueError):
            await db.save_saml_response_id("resp", ttl_seconds=0)

    async def test_response_id_replay_rejected(self, db: AbstractDatabase) -> None:
        assert await db.check_and_record_saml_response_id("resp-1") is True
        assert await db.check_and_record_saml_response_id("resp-1") is False
        assert await db.check_and_record_saml_response_id("resp-2") is True

    async def test_concurrent_response_id_single_winner(
        self, db: AbstractDatabase
    ) -> None:
        results = await asyncio.gather(
            db.check_and_record_saml_response_id("resp-race"),
            db.check_and_record_saml_response_id("resp-race"),
            db.check_and_record_saml_response_id("resp-race"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 2

    async def test_save_response_id_with_ttl_blocks_then_expires(
        self, db: AbstractDatabase
    ) -> None:
        await db.save_saml_response_id("resp-3", ttl_seconds=60)
        assert await db.check_and_record_saml_response_id("resp-3") is False
        await db.save_saml_response_id("resp-4", ttl_seconds=1)
        time.sleep(1.1)
        assert await db.check_and_record_saml_response_id("resp-4") is True

    async def test_user_mapping(self, db: AbstractDatabase) -> None:
        await db.save_saml_user_mapping("nameid-1", "https://sp.test", "user-9")
        assert await db.get_saml_user_mapping("nameid-1", "https://sp.test") == "user-9"
        assert await db.get_saml_user_mapping("nameid-1", "https://other.test") is None
        with pytest.raises(ValueError):
            await db.save_saml_user_mapping("", "https://sp.test", "user-9")


class TestOidc:
    async def test_save_and_get_by_issuer_or_slug(
        self, db: AbstractDatabase
    ) -> None:
        provider = await db.save_oidc_provider(
            {"name": "Okta", "issuer": "https://okta.test", "client_id": "cid"}
        )
        assert provider["id"]
        assert provider["slug"] == "okta"
        assert (await db.get_oidc_provider("https://okta.test"))["id"] == provider["id"]
        assert (await db.get_oidc_provider("okta"))["id"] == provider["id"]
        assert await db.get_oidc_provider("missing") is None

    async def test_requires_issuer_and_name(self, db: AbstractDatabase) -> None:
        with pytest.raises(ValueError):
            await db.save_oidc_provider({"name": "NoIssuer"})
        with pytest.raises(ValueError):
            await db.save_oidc_provider({"issuer": "https://x.test"})

    async def test_duplicate_issuer_rejected(self, db: AbstractDatabase) -> None:
        await db.save_oidc_provider({"name": "One", "issuer": "https://x.test"})
        with pytest.raises(IntegrityError):
            await db.save_oidc_provider({"name": "Two", "issuer": "https://x.test"})

    async def test_whitelisted_update(self, db: AbstractDatabase) -> None:
        await db.save_oidc_provider({"name": "Okta", "issuer": "https://okta.test"})
        updated = await db.update_oidc_provider(
            "https://okta.test",
            {"client_id": "new-cid", "enabled": False, "scopes": ["openid", "email"]},
        )
        assert updated["client_id"] == "new-cid"
        assert updated["enabled"] is False
        assert updated["scopes"] == ["openid", "email"]

    async def test_non_whitelisted_update_rejected(
        self, db: AbstractDatabase
    ) -> None:
        await db.save_oidc_provider({"name": "Okta", "issuer": "https://okta.test"})
        with pytest.raises(ValueError, match="not updatable"):
            await db.update_oidc_provider("https://okta.test", {"id": "evil"})
        with pytest.raises(ValueError, match="not updatable"):
            await db.update_oidc_provider(
                "https://okta.test", {"created_at": "evil", "hacked": True}
            )

    async def test_update_reindexes_issuer_and_slug(
        self, db: AbstractDatabase
    ) -> None:
        await db.save_oidc_provider({"name": "Okta", "issuer": "https://okta.test"})
        await db.update_oidc_provider(
            "https://okta.test",
            {"issuer": "https://okta2.test", "slug": "okta-two"},
        )
        assert await db.get_oidc_provider("https://okta.test") is None
        assert (await db.get_oidc_provider("https://okta2.test"))["slug"] == "okta-two"
        assert (await db.get_oidc_provider("okta-two"))["issuer"] == "https://okta2.test"

    async def test_update_missing_returns_none(self, db: AbstractDatabase) -> None:
        assert await db.update_oidc_provider("missing", {"client_id": "x"}) is None
