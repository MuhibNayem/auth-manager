"""Unit tests for the MongoDB adapter with a mocked motor layer.

No live MongoDB server is used: a minimal in-memory fake stands in for
motor collections, which is enough to verify index creation, whitelist
enforcement, and atomic consume semantics.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from authy_package.config import DatabaseConfig
from authy_package.db.mongodb import (
    MEMBER_UPDATABLE_FIELDS,
    ORG_UPDATABLE_FIELDS,
    USER_UPDATABLE_FIELDS,
    MongoDB,
)



class FakeCursor:
    """Chainable async cursor over an in-memory document list."""

    def __init__(self, docs: List[Dict[str, Any]]) -> None:
        self.docs = list(docs)

    def sort(self, spec: Any, direction: Any = None) -> "FakeCursor":
        if direction is not None:
            spec = [(spec, direction)]
        elif isinstance(spec, str):
            spec = [(spec, 1)]
        for field, direction in reversed(list(spec)):
            self.docs.sort(
                key=lambda d: (d.get(field) is None, d.get(field)),
                reverse=direction < 0,
            )
        return self

    def skip(self, n: int) -> "FakeCursor":
        self.docs = self.docs[n:]
        return self

    def limit(self, n: int) -> "FakeCursor":
        self.docs = self.docs[:n]
        return self

    async def to_dict(self, length: int = None) -> List[Dict[str, Any]]:
        return list(self.docs[:length]) if length else list(self.docs)

    def __aiter__(self):
        async def gen():
            for doc in self.docs:
                yield doc

        return gen()


class FakeCollection:
    """Minimal in-memory stand-in for a motor collection."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.docs: Dict[Any, Dict[str, Any]] = {}
        self.index_calls: List[List[Any]] = []

    async def create_indexes(self, models: List[Any]) -> List[str]:
        self.index_calls.append(list(models))
        return [f"index_{i}" for i in range(len(models))]

    def _matches(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        for key, cond in query.items():
            if key == "$or":
                if not any(self._matches(doc, sub) for sub in cond):
                    return False
                continue
            value = doc.get(key)
            if isinstance(cond, dict):
                for op, expected in cond.items():
                    if op == "$ne" and value == expected:
                        return False
                    if op == "$gt" and not (value is not None and value > expected):
                        return False
                    if op == "$gte" and not (value is not None and value >= expected):
                        return False
                    if op == "$lt" and not (value is not None and value < expected):
                        return False
                    if op == "$lte" and not (value is not None and value <= expected):
                        return False
                    if op == "$in" and value not in expected:
                        return False
                    if op == "$regex" and (value is None or not re.search(expected, value)):
                        return False
            elif value != cond:
                return False
        return True

    def _first(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for doc in self.docs.values():
            if self._matches(doc, query):
                return doc
        return None

    async def insert_one(self, doc: Dict[str, Any]) -> Any:
        from pymongo.errors import DuplicateKeyError

        if doc["_id"] in self.docs:
            raise DuplicateKeyError(f"duplicate key: {doc['_id']!r}")
        self.docs[doc["_id"]] = dict(doc)
        return type("R", (), {"inserted_id": doc["_id"]})()

    async def find_one(
        self, query: Dict[str, Any], projection: Any = None
    ) -> Optional[Dict[str, Any]]:
        doc = self._first(query)
        return dict(doc) if doc else None

    async def find_one_and_delete(
        self, query: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        for key, doc in list(self.docs.items()):
            if self._matches(doc, query):
                del self.docs[key]
                return dict(doc)
        return None

    async def update_one(
        self, query: Dict[str, Any], update: Dict[str, Any], upsert: bool = False
    ) -> Any:
        doc = self._first(query)
        if doc is None:
            return type("R", (), {"matched_count": 0, "modified_count": 0})()
        doc.update(update.get("$set", {}))
        return type("R", (), {"matched_count": 1, "modified_count": 1})()

    async def update_many(
        self, query: Dict[str, Any], update: Dict[str, Any]
    ) -> Any:
        matched = 0
        for doc in self.docs.values():
            if self._matches(doc, query):
                doc.update(update.get("$set", {}))
                matched += 1
        return type("R", (), {"matched_count": matched, "modified_count": matched})()

    async def replace_one(
        self, query: Dict[str, Any], doc: Dict[str, Any], upsert: bool = False
    ) -> Any:
        self.docs[doc["_id"]] = dict(doc)
        return type("R", (), {"matched_count": 1, "modified_count": 1})()

    async def delete_one(self, query: Dict[str, Any]) -> Any:
        for key, doc in list(self.docs.items()):
            if self._matches(doc, query):
                del self.docs[key]
                return type("R", (), {"deleted_count": 1})()
        return type("R", (), {"deleted_count": 0})()

    async def delete_many(self, query: Dict[str, Any]) -> Any:
        removed = 0
        for key, doc in list(self.docs.items()):
            if self._matches(doc, query):
                del self.docs[key]
                removed += 1
        return type("R", (), {"deleted_count": removed})()

    async def count_documents(self, query: Dict[str, Any]) -> int:
        return sum(1 for doc in self.docs.values() if self._matches(doc, query))

    def find(self, query: Dict[str, Any], projection: Any = None) -> FakeCursor:
        return FakeCursor(
            [dict(d) for d in self.docs.values() if self._matches(d, query)]
        )


class FakeDB:
    """Attribute-addressed collection registry (motor database stand-in)."""

    def __init__(self) -> None:
        self._collections: Dict[str, FakeCollection] = {}

    def __getattr__(self, name: str) -> FakeCollection:
        if name.startswith("_"):
            raise AttributeError(name)
        collections = object.__getattribute__(self, "_collections")
        return collections.setdefault(name, FakeCollection(name))


@pytest.fixture
def mongo() -> MongoDB:
    database = MongoDB(
        DatabaseConfig(
            db_type="mongodb",
            connection_string="mongodb://fake:27017",
            db_name="authy_test",
        )
    )
    database._db = FakeDB()
    return database


class TestIndexCreation:
    async def test_connect_indexes_cover_uniqueness_and_ttl(
        self, mongo: MongoDB
    ) -> None:
        await mongo._ensure_indexes()
        db = mongo._db

        user_specs = [m.document for m in db.users.index_calls[0]]
        keys = {tuple(spec["key"].keys()): spec for spec in user_specs}
        assert keys[("email_lowercase",)]["unique"] is True
        assert keys[("email_lowercase",)]["sparse"] is True
        assert keys[("username_lowercase",)]["unique"] is True
        assert keys[("username_lowercase",)]["sparse"] is True
        assert keys[("phone",)]["unique"] is True

        audit_specs = [m.document for m in db.audit_events.index_calls[0]]
        assert any(
            tuple(spec["key"].keys()) == ("sequence",) and spec.get("unique")
            for spec in audit_specs
        )

        ttl_requests = [m.document for m in db.saml_requests.index_calls[0]][0]
        assert ttl_requests.get("expireAfterSeconds") == 0
        ttl_responses = [m.document for m in db.saml_response_ids.index_calls[0]][0]
        assert ttl_responses.get("expireAfterSeconds") == 0

        oidc_specs = [m.document for m in db.oidc_providers.index_calls[0]]
        oidc_keys = {tuple(spec["key"].keys()): spec for spec in oidc_specs}
        assert oidc_keys[("issuer",)]["unique"] is True
        assert oidc_keys[("slug",)]["unique"] is True

        assert db.roles.index_calls[0][0].document.get("unique") is True
        assert db.api_keys.index_calls[0][0].document.get("unique") is True


class TestWhitelistEnforcement:
    async def test_update_user_rejects_unknown_and_operator_keys(
        self, mongo: MongoDB
    ) -> None:
        with pytest.raises(ValueError, match="not updatable"):
            await mongo.update_user("u1", {"hacked": True})
        with pytest.raises(ValueError, match="operator"):
            await mongo.update_user("u1", {"$where": "evil"})
        # id/created_at are outside the whitelist as well.
        with pytest.raises(ValueError):
            await mongo.update_user("u1", {"id": "evil"})

    async def test_update_paths_are_whitelisted(self, mongo: MongoDB) -> None:
        with pytest.raises(ValueError):
            await mongo.update_organization("o1", {"hacked": 1})
        with pytest.raises(ValueError):
            await mongo.update_webhook_endpoint("w1", {"hacked": 1})
        with pytest.raises(ValueError):
            await mongo.update_org_member("o1", "u1", {"user_id": "u2"})
        with pytest.raises(ValueError, match="not updatable"):
            await mongo.update_oidc_provider("x", {"id": "evil"})
        assert {"role"} == MEMBER_UPDATABLE_FIELDS
        assert "name" in ORG_UPDATABLE_FIELDS
        assert "email" in USER_UPDATABLE_FIELDS


class TestCaseInsensitiveLookups:
    async def test_lowercase_fields_stored_and_stripped(
        self, mongo: MongoDB
    ) -> None:
        created = await mongo.create_user(
            {"username": "Alice", "email": "Alice@Example.test"}
        )
        assert "email_lowercase" not in created
        assert "username_lowercase" not in created
        stored = mongo._db.users.docs[created["id"]]
        assert stored["email_lowercase"] == "alice@example.test"
        assert stored["username_lowercase"] == "alice"
        found = await mongo.get_user_by_identifier(email="ALICE@example.TEST")
        assert found["id"] == created["id"]
        found = await mongo.get_user_by_identifier(username="aLiCe")
        assert found["id"] == created["id"]


class TestAtomicOperations:
    async def test_saml_request_consume_is_fetch_and_delete(
        self, mongo: MongoDB
    ) -> None:
        await mongo.save_saml_request("req-1", {"relay": "/x"}, ttl_seconds=60)
        assert "req-1" in mongo._db.saml_requests.docs
        data = await mongo.consume_saml_request("req-1")
        assert data == {"relay": "/x"}
        assert "req-1" not in mongo._db.saml_requests.docs
        assert await mongo.consume_saml_request("req-1") is None

    async def test_expired_saml_request_not_consumable(
        self, mongo: MongoDB
    ) -> None:
        mongo._db.saml_requests.docs["req-old"] = {
            "_id": "req-old",
            "data": {"x": 1},
            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=5),
        }
        assert await mongo.consume_saml_request("req-old") is None

    async def test_response_id_single_winner_via_unique_id(
        self, mongo: MongoDB
    ) -> None:
        assert await mongo.check_and_record_saml_response_id("resp-1") is True
        assert await mongo.check_and_record_saml_response_id("resp-1") is False
        stored = mongo._db.saml_response_ids.docs["resp-1"]
        assert "expires_at" not in stored  # persistent ledger entry

    async def test_revoke_session_is_conditional(self, mongo: MongoDB) -> None:
        await mongo.save_session({"id": "s1", "user_id": "u1"})
        assert await mongo.revoke_session("s1") is True
        assert await mongo.revoke_session("s1") is False
        assert await mongo.revoke_session("missing") is False
        assert await mongo.get_active_sessions("u1") == []


class TestAuditChain:
    async def test_chain_links_and_checksums(
        self, mongo: MongoDB, expected_checksum
    ) -> None:
        first = await mongo.save_audit_event(
            {"event_type": "user.login", "actor": "a1"}
        )
        second = await mongo.save_audit_event(
            {"event_type": "user.login", "actor": "a2"}
        )
        assert first["previous_checksum"] == "0" * 64
        assert second["previous_checksum"] == first["checksum"]
        assert expected_checksum(first) == first["checksum"]
        assert expected_checksum(second) == second["checksum"]
        count = await mongo.save_audit_events([{"event_type": "x"}] * 2)
        assert count == 2
