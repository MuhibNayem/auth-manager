"""Unit tests for DynamoDBAdapter with a stubbed boto3-style client.

The ``FakeDynamoClient`` below is a monkeypatched client: it stores typed
DynamoDB items in a dict and honors the conditional expressions used by
the adapter (attribute_exists / attribute_not_exists / status checks), so
atomicity semantics can be asserted without a live DynamoDB endpoint.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

import pytest
from botocore.exceptions import ClientError

from authy_package.db.dynamodb_adapter import DynamoDBAdapter


def _conditional_check_failed() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
        "Operation",
    )


class FakeDynamoClient:
    """Minimal in-memory DynamoDB stub (typed attribute storage)."""

    def __init__(self) -> None:
        self.tables: Dict[str, Dict[Tuple[str, str], Dict[str, Any]]] = {}

    def _table(self, name: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
        return self.tables.setdefault(name, {})

    @staticmethod
    def _key_of(kwargs: Dict[str, Any]) -> Tuple[str, str]:
        key = kwargs.get("Key")
        if key is None:  # put_item carries Item, not Key
            key = {"PK": kwargs["Item"]["PK"], "SK": kwargs["Item"]["SK"]}
        return key["PK"]["S"], key["SK"]["S"]

    def _item_exists(self, kwargs: Dict[str, Any]) -> bool:
        return self._key_of(kwargs) in self._table(kwargs["TableName"])

    def _check_condition(self, kwargs: Dict[str, Any]) -> None:
        condition = kwargs.get("ConditionExpression")
        if not condition:
            return
        exists = self._item_exists(kwargs)
        if condition.startswith("attribute_not_exists(PK) OR expires_at < :now"):
            if exists:
                item = self._table(kwargs["TableName"])[self._key_of(kwargs)]
                expires = item.get("expires_at")
                now = kwargs["ExpressionAttributeValues"][":now"]["N"]
                if expires is None or float(expires["N"]) >= float(now):
                    raise _conditional_check_failed()
            return
        if condition == "attribute_not_exists(PK)":
            if exists:
                raise _conditional_check_failed()
            return
        if condition.startswith("attribute_exists(PK)"):
            if not exists:
                raise _conditional_check_failed()
            item = self._table(kwargs["TableName"])[self._key_of(kwargs)]
            if "#status = :active" in condition:
                if item.get("status", {}).get("S") != "active":
                    raise _conditional_check_failed()
            if "expires_at > :now" in condition:
                expires = item.get("expires_at", {}).get("N")
                now = kwargs["ExpressionAttributeValues"][":now"]["N"]
                if expires is None or float(expires) <= float(now):
                    raise _conditional_check_failed()

    async def put_item(self, **kwargs: Any) -> Dict[str, Any]:
        self._check_condition(kwargs)
        item = kwargs["Item"]
        self._table(kwargs["TableName"])[(item["PK"]["S"], item["SK"]["S"])] = item
        return {}

    async def get_item(self, **kwargs: Any) -> Dict[str, Any]:
        item = self._table(kwargs["TableName"]).get(self._key_of(kwargs))
        return {"Item": item} if item else {}

    async def delete_item(self, **kwargs: Any) -> Dict[str, Any]:
        self._check_condition(kwargs)
        item = self._table(kwargs["TableName"]).pop(self._key_of(kwargs), None)
        response: Dict[str, Any] = {}
        if kwargs.get("ReturnValues") == "ALL_OLD" and item:
            response["Attributes"] = item
        return response

    async def update_item(self, **kwargs: Any) -> Dict[str, Any]:
        self._check_condition(kwargs)
        table = self._table(kwargs["TableName"])
        key = self._key_of(kwargs)
        item = table.get(key)
        if item is None:
            raise _conditional_check_failed()
        names = kwargs.get("ExpressionAttributeNames", {})
        values = kwargs.get("ExpressionAttributeValues", {})
        assignment = kwargs["UpdateExpression"].lstrip("SET ")
        for part in assignment.split(","):
            placeholder, value_placeholder = [p.strip() for p in part.split("=")]
            item[names.get(placeholder, placeholder)] = values[value_placeholder]
        return {"Attributes": item}

    async def query(self, **kwargs: Any) -> Dict[str, Any]:
        items = list(self._table(kwargs["TableName"]).values())
        # Honor the partition-key equality of the key condition; range
        # clauses and client-side filters are exercised by the adapter.
        values = kwargs.get("ExpressionAttributeValues", {})
        condition = kwargs.get("KeyConditionExpression", "")
        if ":pk" in values:
            pk_value = values[":pk"]["S"]
            if "GSI1PK = :pk" in condition:
                attr = "GSI1PK"
            elif "GSI2PK = :pk" in condition:
                attr = "GSI2PK"
            else:
                attr = "PK"
            items = [
                item for item in items if item.get(attr, {}).get("S") == pk_value
            ]
        limit = kwargs.get("Limit")
        if limit:
            items = items[:limit]
        return {"Items": items}

    async def scan(self, **kwargs: Any) -> Dict[str, Any]:
        return {"Items": list(self._table(kwargs["TableName"]).values())}

    async def list_tables(self, **kwargs: Any) -> Dict[str, Any]:
        return {"TableNames": list(self.tables)}

    async def describe_table(self, **kwargs: Any) -> Dict[str, Any]:
        return {"Table": {"TableName": kwargs["TableName"]}}


@pytest.fixture
def adapter() -> DynamoDBAdapter:
    dynamo = DynamoDBAdapter(
        {"table_prefix": "authy_test_", "region": "us-east-1"}
    )
    dynamo.client = FakeDynamoClient()
    dynamo.is_connected = True
    return dynamo


class TestSerialization:
    def test_bool_serialized_before_int(self, adapter: DynamoDBAdapter) -> None:
        # True is an int subclass: it MUST land in BOOL, not N.
        assert adapter._serialize_item({"mfa_enabled": True}) == {
            "mfa_enabled": {"BOOL": True}
        }
        assert adapter._serialize_item({"count": 1}) == {"count": {"N": "1"}}
        assert adapter._serialize_item({"score": 1.5}) == {"score": {"N": "1.5"}}
        assert adapter._serialize_item({"tags": ["a", "b"]}) == {
            "tags": {"SS": ["a", "b"]}
        }
        assert adapter._serialize_item({"flags": [True, False]}) == {
            "flags": {"L": [{"BOOL": True}, {"BOOL": False}]}
        }
        assert adapter._serialize_item({"meta": None}) == {"meta": {"NULL": True}}

    def test_roundtrip(self, adapter: DynamoDBAdapter) -> None:
        original = {
            "id": "x",
            "mfa_enabled": True,
            "count": 3,
            "tags": ["a"],
            "nested": {"deep": True},
        }
        assert adapter._deserialize_item(adapter._serialize_item(original)) == original


class TestAuditPkUniqueness:
    async def test_same_second_events_get_distinct_pks(
        self, adapter: DynamoDBAdapter
    ) -> None:
        frozen = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        first = await adapter.save_audit_event(
            {"event_type": "user.login", "actor": "alice", "timestamp": frozen}
        )
        second = await adapter.save_audit_event(
            {"event_type": "user.login", "actor": "alice", "timestamp": frozen}
        )
        assert first["id"] != second["id"]
        audit_table = adapter.client.tables["authy_test_audit_events"]
        pks = sorted(pk for pk, _ in audit_table)
        assert pks == sorted([f"AUDIT#{first['id']}", f"AUDIT#{second['id']}"])
        assert len(pks) == len(set(pks))

    async def test_chain_links_and_checksums(self, adapter: DynamoDBAdapter) -> None:
        first = await adapter.save_audit_event({"event_type": "a", "actor": "x"})
        second = await adapter.save_audit_event({"event_type": "b", "actor": "y"})
        assert first["previous_checksum"] == "0" * 64
        assert second["previous_checksum"] == first["checksum"]
        assert first["sequence"] == 1
        assert second["sequence"] == 2
        fetched = await adapter.get_audit_event(second["id"])
        assert fetched["checksum"] == second["checksum"]


class TestActiveSessionFiltering:
    async def test_get_active_sessions_filters_status(
        self, adapter: DynamoDBAdapter
    ) -> None:
        await adapter.save_session({"id": "s1", "user_id": "u1"})
        await adapter.save_session(
            {"id": "s2", "user_id": "u1", "status": "revoked"}
        )
        await adapter.save_session({"id": "s3", "user_id": "u1"})
        await adapter.save_session({"id": "s4", "user_id": "u2"})
        active = await adapter.get_active_sessions("u1")
        assert {s["id"] for s in active} == {"s1", "s3"}

    async def test_revoke_session_conditional_single_winner(
        self, adapter: DynamoDBAdapter
    ) -> None:
        await adapter.save_session({"id": "s1", "user_id": "u1"})
        results = await asyncio.gather(
            adapter.revoke_session("s1"),
            adapter.revoke_session("s1"),
            adapter.revoke_session("s1"),
        )
        assert results.count(True) == 1
        assert results.count(False) == 2
        assert await adapter.revoke_session("missing") is False


class TestConditionalConsumes:
    async def test_saml_request_consume_one_op_single_winner(
        self, adapter: DynamoDBAdapter
    ) -> None:
        await adapter.save_saml_request("req-1", {"relay": "/x"}, ttl_seconds=60)
        results = await asyncio.gather(
            adapter.consume_saml_request("req-1"),
            adapter.consume_saml_request("req-1"),
            adapter.consume_saml_request("req-1"),
        )
        winners = [r for r in results if r is not None]
        assert winners == [{"relay": "/x"}]
        assert adapter.client.tables["authy_test_saml_requests"] == {}

    async def test_saml_consume_expired_returns_none(
        self, adapter: DynamoDBAdapter
    ) -> None:
        await adapter.save_saml_request("req-2", {"x": 1}, ttl_seconds=1)
        # Force the stored expiry into the past.
        item = adapter.client.tables["authy_test_saml_requests"][
            ("SAML_REQ#req-2", "PROFILE")
        ]
        item["expires_at"] = {"N": "1"}
        assert await adapter.consume_saml_request("req-2") is None

    async def test_response_id_replay_blocked(
        self, adapter: DynamoDBAdapter
    ) -> None:
        assert await adapter.check_and_record_saml_response_id("resp-1") is True
        assert await adapter.check_and_record_saml_response_id("resp-1") is False
        await adapter.save_saml_response_id("resp-2", ttl_seconds=1)
        item = adapter.client.tables["authy_test_saml_response_ids"][
            ("SAML_RESP#resp-2", "PROFILE")
        ]
        item["expires_at"] = {"N": "1"}  # expired -> no longer blocks
        assert await adapter.check_and_record_saml_response_id("resp-2") is True


class TestContractSignatures:
    async def test_get_user_by_identifier_keyword_only(
        self, adapter: DynamoDBAdapter
    ) -> None:
        with pytest.raises(TypeError):
            await adapter.get_user_by_identifier("positional@x.test")  # type: ignore[misc]
        assert await adapter.get_user_by_identifier(email="nobody@x.test") is None

    async def test_oidc_update_whitelist_rejected(
        self, adapter: DynamoDBAdapter
    ) -> None:
        with pytest.raises(ValueError, match="not updatable"):
            await adapter.update_oidc_provider("issuer", {"id": "evil"})

    async def test_circuit_breaker_and_observability_wired(
        self, adapter: DynamoDBAdapter
    ) -> None:
        from authy_package.db.enterprise_utils import (
            CircuitBreaker,
            ObservabilityMixin,
        )

        assert isinstance(adapter.circuit_breaker, CircuitBreaker)
        assert isinstance(adapter, ObservabilityMixin)
        await adapter.get_user_by_id("missing")
        metrics = adapter.get_metrics()
        assert metrics["total_operations"] >= 1
