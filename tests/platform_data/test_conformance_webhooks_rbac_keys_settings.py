"""Conformance: webhooks, RBAC, API keys, settings."""

from __future__ import annotations

import hashlib

import pytest

from authy_package.db.abstract_db import AbstractDatabase
from authy_package.errors import IntegrityError



class TestWebhooks:
    async def test_endpoint_crud(self, db: AbstractDatabase) -> None:
        endpoint = await db.save_webhook_endpoint(
            {"url": "https://hooks.x.test/a", "events": ["user.created"]}
        )
        assert endpoint["id"]
        assert endpoint["enabled"] is True
        fetched = await db.get_webhook_endpoint(endpoint["id"])
        assert fetched["url"] == "https://hooks.x.test/a"
        updated = await db.update_webhook_endpoint(
            endpoint["id"], {"enabled": False, "events": []}
        )
        assert updated["enabled"] is False
        assert len(await db.list_webhook_endpoints()) == 1
        assert await db.delete_webhook_endpoint(endpoint["id"]) is True
        assert await db.get_webhook_endpoint(endpoint["id"]) is None
        assert await db.delete_webhook_endpoint(endpoint["id"]) is False
        with pytest.raises(ValueError):
            await db.save_webhook_endpoint({"events": []})

    async def test_deliveries_newest_first_and_limited(
        self, db: AbstractDatabase, to_datetime
    ) -> None:
        endpoint = await db.save_webhook_endpoint({"url": "https://hooks.x.test/a"})
        for i in range(5):
            await db.save_webhook_delivery(
                {
                    "endpoint_id": endpoint["id"],
                    "event_type": "user.created",
                    "status": "success" if i % 2 == 0 else "failed",
                    "response_code": 200 if i % 2 == 0 else 500,
                }
            )
        deliveries = await db.get_webhook_deliveries(endpoint["id"], limit=3)
        assert len(deliveries) == 3
        timestamps = [to_datetime(d["created_at"]) for d in deliveries]
        assert timestamps == sorted(timestamps, reverse=True)
        with pytest.raises(IntegrityError):
            await db.save_webhook_delivery({"endpoint_id": "missing"})

    async def test_endpoint_delete_removes_deliveries(
        self, db: AbstractDatabase
    ) -> None:
        endpoint = await db.save_webhook_endpoint({"url": "https://hooks.x.test/a"})
        await db.save_webhook_delivery({"endpoint_id": endpoint["id"]})
        await db.delete_webhook_endpoint(endpoint["id"])
        assert await db.get_webhook_deliveries(endpoint["id"]) == []


class TestRBAC:
    async def test_role_crud_and_upsert(self, db: AbstractDatabase) -> None:
        role = await db.save_role({"name": "editor", "permissions": ["docs:write"]})
        assert role["id"]
        assert (await db.get_role(role["id"]))["name"] == "editor"
        assert len(await db.list_roles()) == 1
        updated = await db.save_role(
            {"id": role["id"], "name": "editor", "permissions": ["a", "b"]}
        )
        assert updated["id"] == role["id"]
        assert updated["permissions"] == ["a", "b"]
        assert len(await db.list_roles()) == 1
        assert await db.delete_role(role["id"]) is True
        assert await db.delete_role(role["id"]) is False
        with pytest.raises(ValueError):
            await db.save_role({"permissions": []})
        await db.save_role({"name": "editor"})
        with pytest.raises(IntegrityError):
            await db.save_role({"name": "editor"})

    async def test_assignments(self, db: AbstractDatabase) -> None:
        with pytest.raises(IntegrityError):
            await db.save_role_assignment({"user_id": "u1", "role_id": "missing"})
        editor = await db.save_role({"name": "editor"})
        admin = await db.save_role({"name": "admin"})
        with pytest.raises(ValueError):
            await db.save_role_assignment({"role_id": editor["id"]})
        a1 = await db.save_role_assignment(
            {"user_id": "u1", "role_id": editor["id"], "scope_type": "org", "scope_id": "o1"}
        )
        await db.save_role_assignment(
            {"user_id": "u1", "role_id": admin["id"], "scope_type": "global"}
        )
        await db.save_role_assignment(
            {"user_id": "u2", "role_id": editor["id"], "scope_type": "org", "scope_id": "o2"}
        )
        assert len(await db.query_role_assignments(user_id="u1")) == 2
        assert len(await db.query_role_assignments(role_id=editor["id"])) == 2
        combined = await db.query_role_assignments(
            user_id="u1", role_id=editor["id"], scope_type="org", scope_id="o1"
        )
        assert len(combined) == 1 and combined[0]["id"] == a1["id"]
        with pytest.raises(IntegrityError):
            await db.delete_role(editor["id"])
        assert await db.delete_role_assignment(a1["id"]) is True
        assert await db.delete_role_assignment(a1["id"]) is False


class TestApiKeys:
    async def test_store_hash_only_and_revoke(self, db: AbstractDatabase) -> None:
        key_hash = hashlib.sha256(b"authy_ak_secret-value").hexdigest()
        record = await db.save_api_key(
            {"name": "ci-key", "key_hash": key_hash, "scopes": ["users:read"]}
        )
        assert record["id"]
        assert record["revoked"] is False
        fetched = await db.get_api_key_by_hash(key_hash)
        assert fetched["id"] == record["id"]
        assert await db.get_api_key_by_hash("missing") is None
        assert len(await db.list_api_keys()) == 1
        assert await db.revoke_api_key(record["id"]) is True
        revoked = await db.get_api_key_by_hash(key_hash)
        assert revoked["revoked"] is True
        assert "revoked_at" in revoked
        assert await db.revoke_api_key("missing") is False

    async def test_validation(self, db: AbstractDatabase) -> None:
        with pytest.raises(ValueError, match="never"):
            await db.save_api_key({"name": "bad", "key": "authy_ak_plaintext"})
        with pytest.raises(ValueError):
            await db.save_api_key({"name": "bad"})
        key_hash = hashlib.sha256(b"same-key").hexdigest()
        await db.save_api_key({"name": "one", "key_hash": key_hash})
        with pytest.raises(IntegrityError):
            await db.save_api_key({"name": "two", "key_hash": key_hash})


class TestSettings:
    async def test_roundtrip_json_values(self, db: AbstractDatabase) -> None:
        await db.set_setting("branding", {"logo": "https://x/logo.png", "theme": "dark"})
        await db.set_setting("features", ["mfa", "sso"])
        await db.set_setting("limit", 5)
        assert await db.get_setting("branding") == {
            "logo": "https://x/logo.png",
            "theme": "dark",
        }
        assert await db.get_setting("features") == ["mfa", "sso"]
        assert await db.get_setting("limit") == 5
        assert await db.get_setting("missing") is None
        with pytest.raises(ValueError):
            await db.set_setting("bad", object())
        with pytest.raises(ValueError):
            await db.set_setting("", "x")
