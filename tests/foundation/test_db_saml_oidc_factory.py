"""Tests for §4 SAML ledgers, OIDC providers, and the db factory."""

from __future__ import annotations

import asyncio
import time

import pytest

from tessera.config import AuthConfig, DatabaseConfig
from tessera.db import InMemoryDatabase, get_database
from tessera.errors import ConfigError, IntegrityError


class TestSaml:
    async def test_request_save_consume_single_use(self, db: InMemoryDatabase) -> None:
        await db.save_saml_request("req-1", {"relay_state": "/dash"}, ttl_seconds=60)
        data = await db.consume_saml_request("req-1")
        assert data == {"relay_state": "/dash"}
        assert await db.consume_saml_request("req-1") is None

    async def test_concurrent_consume_single_winner(self, db: InMemoryDatabase) -> None:
        await db.save_saml_request("req-2", {"x": 1}, ttl_seconds=60)
        results = await asyncio.gather(
            db.consume_saml_request("req-2"),
            db.consume_saml_request("req-2"),
            db.consume_saml_request("req-2"),
        )
        winners = [r for r in results if r is not None]
        assert len(winners) == 1

    async def test_expired_request_returns_none(self, db: InMemoryDatabase) -> None:
        await db.save_saml_request("req-3", {"x": 1}, ttl_seconds=60)
        data, _ = db._saml_requests["req-3"]
        db._saml_requests["req-3"] = (data, time.time() - 1)
        assert await db.consume_saml_request("req-3") is None

    async def test_ttl_validation(self, db: InMemoryDatabase) -> None:
        with pytest.raises(ValueError):
            await db.save_saml_request("req", {}, ttl_seconds=0)

    async def test_response_id_replay_rejected(self, db: InMemoryDatabase) -> None:
        assert await db.check_and_record_saml_response_id("resp-1") is True
        assert await db.check_and_record_saml_response_id("resp-1") is False
        assert await db.check_and_record_saml_response_id("resp-2") is True

    async def test_concurrent_response_id_single_winner(self, db: InMemoryDatabase) -> None:
        results = await asyncio.gather(
            db.check_and_record_saml_response_id("resp-race"),
            db.check_and_record_saml_response_id("resp-race"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 1

    async def test_save_response_id_with_ttl_and_replay(self, db: InMemoryDatabase) -> None:
        await db.save_saml_response_id("resp-3", ttl_seconds=60)
        assert await db.check_and_record_saml_response_id("resp-3") is False

    async def test_response_id_ttl_expiry_allows_fresh_check(
        self, db: InMemoryDatabase
    ) -> None:
        await db.save_saml_response_id("resp-4", ttl_seconds=60)
        db._saml_response_ids["resp-4"] = time.time() - 1
        assert await db.check_and_record_saml_response_id("resp-4") is True

    async def test_user_mapping(self, db: InMemoryDatabase) -> None:
        await db.save_saml_user_mapping("nameid-1", "https://sp.test", "user-9")
        assert await db.get_saml_user_mapping("nameid-1", "https://sp.test") == "user-9"
        assert await db.get_saml_user_mapping("nameid-1", "https://other.test") is None
        with pytest.raises(ValueError):
            await db.save_saml_user_mapping("", "https://sp.test", "user-9")


class TestOidc:
    async def test_save_and_get_by_issuer_or_slug(self, db: InMemoryDatabase) -> None:
        provider = await db.save_oidc_provider(
            {
                "name": "Okta",
                "issuer": "https://okta.test",
                "client_id": "cid",
            }
        )
        assert provider["id"]
        assert provider["slug"] == "okta"
        assert (await db.get_oidc_provider("https://okta.test"))["id"] == provider["id"]
        assert (await db.get_oidc_provider("okta"))["id"] == provider["id"]
        assert await db.get_oidc_provider("missing") is None

    async def test_requires_issuer_and_name(self, db: InMemoryDatabase) -> None:
        with pytest.raises(ValueError):
            await db.save_oidc_provider({"name": "NoIssuer"})
        with pytest.raises(ValueError):
            await db.save_oidc_provider({"issuer": "https://x.test"})

    async def test_duplicate_issuer_rejected(self, db: InMemoryDatabase) -> None:
        await db.save_oidc_provider({"name": "One", "issuer": "https://x.test"})
        with pytest.raises(IntegrityError):
            await db.save_oidc_provider({"name": "Two", "issuer": "https://x.test"})

    async def test_whitelisted_update(self, db: InMemoryDatabase) -> None:
        await db.save_oidc_provider({"name": "Okta", "issuer": "https://okta.test"})
        updated = await db.update_oidc_provider(
            "https://okta.test",
            {"client_id": "new-cid", "enabled": False, "scopes": ["openid", "email"]},
        )
        assert updated["client_id"] == "new-cid"
        assert updated["enabled"] is False
        assert updated["scopes"] == ["openid", "email"]

    async def test_non_whitelisted_update_rejected(self, db: InMemoryDatabase) -> None:
        await db.save_oidc_provider({"name": "Okta", "issuer": "https://okta.test"})
        with pytest.raises(ValueError, match="not updatable"):
            await db.update_oidc_provider("https://okta.test", {"id": "evil"})
        with pytest.raises(ValueError, match="not updatable"):
            await db.update_oidc_provider(
                "https://okta.test", {"created_at": "evil", "hacked": True}
            )

    async def test_update_reindexes_issuer_and_slug(self, db: InMemoryDatabase) -> None:
        await db.save_oidc_provider({"name": "Okta", "issuer": "https://okta.test"})
        await db.update_oidc_provider(
            "https://okta.test",
            {"issuer": "https://okta2.test", "slug": "okta-two"},
        )
        assert await db.get_oidc_provider("https://okta.test") is None
        assert (await db.get_oidc_provider("https://okta2.test"))["slug"] == "okta-two"
        assert (await db.get_oidc_provider("okta-two"))["issuer"] == "https://okta2.test"

    async def test_update_missing_returns_none(self, db: InMemoryDatabase) -> None:
        assert await db.update_oidc_provider("missing", {"client_id": "x"}) is None


class TestFactory:
    def test_memory_factory(self) -> None:
        config = AuthConfig(database=DatabaseConfig(db_type="memory"))
        database = get_database(config)
        assert isinstance(database, InMemoryDatabase)

    def test_factory_accepts_database_config_directly(self) -> None:
        database = get_database(DatabaseConfig(db_type="memory"))
        assert isinstance(database, InMemoryDatabase)

    def test_unknown_db_type_raises_config_error(self) -> None:
        with pytest.raises(ConfigError):
            get_database(DatabaseConfig(db_type="neo4j"))

    def test_lazy_adapter_import_is_guarded(self) -> None:
        # `import tessera.db` itself must always work; adapter access
        # either resolves (when the adapter team's module imports cleanly)
        # or raises a helpful ImportError — never an unguarded crash.
        import tessera.db as db_module

        for name in ("SQLDatabase", "MongoDB", "DynamoDBAdapter"):
            try:
                cls = getattr(db_module, name)
                assert isinstance(cls, type)
            except ImportError as exc:
                assert "unavailable" in str(exc)

    def test_missing_attribute_raises_attribute_error(self) -> None:
        import tessera.db as db_module

        with pytest.raises(AttributeError):
            db_module.DoesNotExist  # noqa: B018
