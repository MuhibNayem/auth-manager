"""DynamoDB adapter implementing the full §4 contract (CONTRACTS.md).

Re-based on the unified :class:`AbstractDatabase` contract while keeping the
existing single-table-per-entity PK/SK key design. Resilience wiring
(:class:`CircuitBreaker`, :class:`ObservabilityMixin`, retries) is retained
from :mod:`authy_package.db.enterprise_utils`.

Key design (per-entity tables, ``{table_prefix}{entity}``):

===========  ===============================================================
Entity       Keys
===========  ===============================================================
users        ``PK=USER#{id}``, ``SK=PROFILE``, ``GSI1PK=EMAIL#{email}``
sessions     ``PK=SESSION#{id}``, ``SK=PROFILE``,
             ``GSI1PK=USER#{user_id}``, ``GSI1SK=SESSION#{id}``
organizations``PK=ORG#{id}``, ``SK=PROFILE``, ``GSI1PK=SLUG#{slug}``
org_members  ``PK=ORG#{org_id}``, ``SK=MEMBER#{user_id}``,
             ``GSI1PK=USER#{user_id}``, ``GSI1SK=ORG#{org_id}``
invitations  ``PK=INVITE#{id}``, ``SK=PROFILE``
audit_events ``PK=AUDIT#{event_id}`` (event id in the PK: no same-second
             collisions), ``SK=PROFILE``, ``GSI1PK=ACTOR#{actor}``,
             ``GSI2PK=EVENT#{event_type}``, GSI SKs = ISO timestamp
webhooks     ``PK=WEBHOOK#{id}``, ``SK=PROFILE``
deliveries   ``PK=DELIVERY#{endpoint_id}``,
             ``SK=DELIVERY#{created_at}#{id}``
roles        ``PK=ROLE#{id}``, ``SK=PROFILE``
assignments  ``PK=ASSIGN#{id}``, ``SK=PROFILE``, ``GSI1PK=USER#{user_id}``
api_keys     ``PK=APIKEY#{id}``, ``SK=PROFILE``, ``GSI1PK=HASH#{key_hash}``
settings     ``PK=SETTING#{key}``, ``SK=PROFILE``
saml reqs    ``PK=SAML_REQ#{request_id}``, ``SK=PROFILE`` (+expires_at TTL)
saml resp ids``PK=SAML_RESP#{response_id}``, ``SK=PROFILE``
saml maps    ``PK=SAML_MAP#{name_id}\\x1f{sp_entity_id}``, ``SK=PROFILE``
oidc         ``PK=OIDC#{issuer}``, ``SK=PROFILE``
===========  ===============================================================

Atomicity: session revocation and API-key revocation use conditional
updates; SAML request consume is a conditional ``delete_item`` with
``ReturnValues=ALL_OLD`` (single statement, exactly one winner); SAML
response-id recording is a conditional ``put_item``.

Scan-based fallbacks (key design cannot serve these directly; each is
documented inline and listed in :data:`SCAN_FALLBACK_OPERATIONS`):
``list_users``, ``count_users``, username/phone identifier lookups and
identifier-uniqueness checks, ``get_invitation_by_token``,
``get_pending_invitations``, ``list_organizations``, organization delete
cascades for invitations, ``list_webhook_endpoints``, ``list_roles``,
role-name uniqueness checks, ``query_role_assignments``, role-assignment
existence checks, ``list_api_keys``, audit chain-last lookup, audit
search/statistics/time-series/pruning without an actor or single
event_type filter, OIDC slug lookups and slug-uniqueness checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from authy_package.db.abstract_db import AbstractDatabase
from authy_package.db.enterprise_utils import (
    CircuitBreaker,
    CircuitBreakerConfig,
    ObservabilityMixin,
    RetryConfig,
    with_retry,
)
from authy_package.db.memory import GENESIS_CHECKSUM, OIDC_UPDATABLE_FIELDS
from authy_package.errors import IntegrityError

try:  # pragma: no cover - trivial import guard
    from botocore.exceptions import ClientError

    BOTOCORE_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without botocore
    BOTOCORE_AVAILABLE = False
    ClientError = None  # type: ignore[assignment,misc]

logger = logging.getLogger("authy.db.dynamodb")

__all__ = ["DynamoDBAdapter", "SCAN_FALLBACK_OPERATIONS"]

#: Fields assigned by the database; excluded from the audit checksum payload.
_AUDIT_DB_ASSIGNED_FIELDS = frozenset({"id", "sequence", "checksum"})

#: Conditional-check failure code for conditional put/update/delete.
_CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"

#: Contract methods (or sub-paths of them) served by scan-based fallbacks
#: because the PK/SK key design cannot serve them with a direct query.
SCAN_FALLBACK_OPERATIONS = (
    "list_users",
    "count_users",
    "get_user_by_identifier (username/phone)",
    "create_user/update_user identifier uniqueness (username/phone)",
    "get_invitation_by_token",
    "get_pending_invitations",
    "list_organizations",
    "delete_organization (invitation cascade lookup)",
    "list_webhook_endpoints",
    "list_roles",
    "save_role name uniqueness check",
    "query_role_assignments",
    "delete_role assignment existence check",
    "list_api_keys",
    "save_audit_event chain-last lookup",
    "search_audit_events (without actor or single event_type filter)",
    "get_audit_statistics",
    "get_audit_time_series",
    "delete_audit_events_before",
    "get_oidc_provider (slug path)",
    "update_oidc_provider (slug path / slug uniqueness)",
    "save_oidc_provider slug uniqueness check",
)


def _utcnow() -> datetime:
    """Timezone-aware UTC now (§0.5)."""
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    """ISO-8601 UTC timestamp (lexicographically monotonic)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _new_id() -> str:
    """Random id from the secrets module (§0.3)."""
    return secrets.token_hex(16)


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    """Deterministic JSON encoding for audit checksums (memory.py-exact)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _slugify(value: str) -> str:
    """Derive a URL-safe slug from a name (memory.py-exact)."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "org"


def _placeholder(key: str) -> str:
    """Expression-safe placeholder for a DynamoDB attribute name."""
    return "#" + re.sub(r"[^0-9A-Za-z_]", "_", str(key))


#: Internal key/derived attributes never returned as record fields.
_INTERNAL_KEYS = frozenset(
    {"PK", "SK", "GSI1PK", "GSI1SK", "GSI2PK", "GSI2SK"}
)


class DynamoDBAdapter(AbstractDatabase, ObservabilityMixin):
    """Enterprise-grade DynamoDB adapter for the §4 database contract.

    Args:
        config: A :class:`~authy_package.config.DatabaseConfig` (its
            ``connection_string`` is used as the DynamoDB ``endpoint_url``
            for DynamoDB Local/LocalStack) or a plain dict with keys
            ``table_prefix``, ``region``, ``endpoint_url``.
    """

    def __init__(self, config: Any = None) -> None:
        ObservabilityMixin.__init__(self)
        if isinstance(config, dict):
            cfg = dict(config)
        else:
            cfg = {
                "endpoint_url": (
                    getattr(config, "connection_string", "") or None
                ),
                "table_prefix": getattr(config, "table_prefix", "authy_"),
                "region": getattr(config, "region", None),
            }
        self.config = cfg
        self.table_prefix = cfg.get("table_prefix", "authy_")
        self.region = cfg.get("region") or "us-east-1"
        self.endpoint_url = cfg.get("endpoint_url")
        self.client = None
        self.is_connected = False

        # Circuit breaker for resilience (kept from the enterprise wiring).
        self.circuit_breaker = CircuitBreaker(
            CircuitBreakerConfig(failure_threshold=5, recovery_timeout=60.0)
        )
        self.retry_config = RetryConfig(
            max_retries=3, base_delay=0.5, exponential_base=2.0
        )
        # Serializes hash-chain appends within this process.
        self._audit_lock = asyncio.Lock()

    # -- lifecycle -----------------------------------------------------------

    @with_retry()
    async def connect(self) -> None:
        """Initialize the DynamoDB client via aioboto3 (credential chain)."""
        try:
            import aioboto3
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "DynamoDBAdapter requires aioboto3 ('pip install aioboto3')"
            ) from exc

        logger.info("Initializing DynamoDB connection in region %s...", self.region)
        client_kwargs: Dict[str, Any] = {
            "service_name": "dynamodb",
            "region_name": self.region,
            "endpoint_url": self.endpoint_url,
        }
        access_key = self.config.get("access_key")
        secret_key = self.config.get("secret_key")
        if access_key and secret_key:
            logger.warning(
                "Using explicit AWS credentials from config; this should ONLY "
                "be used for local development. Prefer IAM roles/IRSA/SSO."
            )
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key

        session = aioboto3.Session()
        self.client = await session.client(**client_kwargs).__aenter__()
        await self._verify_permissions()
        self.is_connected = True
        logger.info("DynamoDB connection established successfully")

    async def _verify_permissions(self) -> None:
        """Best-effort permission probe (ListTables); never fails connect."""
        try:
            await self.client.list_tables(Limit=1)
            logger.debug("DynamoDB permissions verified (ListTables successful)")
        except Exception as exc:  # noqa: BLE001 - advisory probe only
            logger.warning("Permission verification failed: %s", exc)

    async def close(self) -> None:
        """Close DynamoDB connections."""
        if self.client is not None:
            exit_method = getattr(self.client, "__aexit__", None)
            if exit_method is not None:
                await exit_method(None, None, None)
            self.client = None
        self.is_connected = False
        logger.info("DynamoDB connections closed")

    async def health_check(self) -> bool:
        """``True`` when the users table is describable."""
        if self.client is None:
            return False
        start = time.time()
        try:
            await self.client.describe_table(
                TableName=self._get_table_name("users")
            )
            logger.debug(
                "DynamoDB health check OK (%.1fms)",
                (time.time() - start) * 1000,
            )
            return True
        except Exception:  # noqa: BLE001 - health checks report, never raise
            logger.exception("DynamoDB health check failed")
            return False

    def _get_table_name(self, entity: str) -> str:
        return f"{self.table_prefix}{entity}"

    async def _execute_with_circuit_breaker(self, operation: str, func, *args, **kwargs):
        """Execute a DynamoDB operation with breaker + observability."""
        return await self.execute_with_observation(
            operation, self.circuit_breaker.call, func, *args, **kwargs
        )

    @staticmethod
    def _is_conditional_check_failed(exc: Exception) -> bool:
        return (
            ClientError is not None
            and isinstance(exc, ClientError)
            and exc.response.get("Error", {}).get("Code")
            == _CONDITIONAL_CHECK_FAILED
        )

    # -- serialization ---------------------------------------------------------

    def _serialize_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Python types to DynamoDB attribute types."""
        return {key: self._serialize_value(value) for key, value in item.items()}

    def _serialize_value(self, value: Any) -> Dict[str, Any]:
        # bool MUST be checked before int (bool is an int subclass).
        if isinstance(value, bool):
            return {"BOOL": value}
        if isinstance(value, str):
            return {"S": value}
        if isinstance(value, (int, float)):
            return {"N": str(value)}
        if isinstance(value, datetime):
            return {"S": _iso(value)}
        if isinstance(value, dict):
            return {"M": self._serialize_item(value)}
        if isinstance(value, (list, tuple)):
            values = list(value)
            if not values:
                return {"L": []}
            if all(isinstance(v, str) for v in values):
                return {"SS": values}
            if all(isinstance(v, bool) for v in values):
                return {"L": [{"BOOL": v} for v in values]}
            if all(
                isinstance(v, (int, float)) and not isinstance(v, bool)
                for v in values
            ):
                return {"NS": [str(v) for v in values]}
            return {"L": [self._serialize_value(v) for v in values]}
        if value is None:
            return {"NULL": True}
        return {"S": str(value)}

    def _deserialize_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB attribute types back to Python types."""
        if not item:
            return {}
        return {
            key: self._deserialize_value(value) for key, value in item.items()
        }

    def _deserialize_value(self, value: Dict[str, Any]) -> Any:
        if "S" in value:
            return value["S"]
        if "N" in value:
            number = Decimal(value["N"])
            return int(number) if number % 1 == 0 else float(number)
        if "BOOL" in value:
            return value["BOOL"]
        if "M" in value:
            return self._deserialize_item(value["M"])
        if "L" in value:
            return [self._deserialize_value(v) for v in value["L"]]
        if "SS" in value:
            return list(value["SS"])
        if "NS" in value:
            numbers = []
            for raw in value["NS"]:
                number = Decimal(raw)
                numbers.append(int(number) if number % 1 == 0 else float(number))
            return numbers
        if "NULL" in value:
            return None
        return None

    @staticmethod
    def _record_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
        """Strip internal key attributes from a deserialized item."""
        return {
            key: value
            for key, value in item.items()
            if key not in _INTERNAL_KEYS
        }

    async def _get_record(
        self, table_name: str, pk: str, sk: str = "PROFILE"
    ) -> Optional[Dict[str, Any]]:
        """Direct-key fetch; returns a clean record or ``None``."""
        response = await self._execute_with_circuit_breaker(
            "get_item",
            self.client.get_item,
            TableName=table_name,
            Key={"PK": {"S": pk}, "SK": {"S": sk}},
        )
        item = response.get("Item")
        if not item:
            return None
        return self._record_from_item(self._deserialize_item(item))

    async def _scan_all(
        self,
        table_name: str,
        *,
        filter_expression: Optional[str] = None,
        expression_attribute_values: Optional[Dict[str, Any]] = None,
        expression_attribute_names: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan a whole table (all pages). DOCUMENTED FALLBACK where used."""
        kwargs: Dict[str, Any] = {"TableName": table_name}
        if filter_expression:
            kwargs["FilterExpression"] = filter_expression
        if expression_attribute_values:
            kwargs["ExpressionAttributeValues"] = expression_attribute_values
        if expression_attribute_names:
            kwargs["ExpressionAttributeNames"] = expression_attribute_names
        items: List[Dict[str, Any]] = []
        while True:
            response = await self._execute_with_circuit_breaker(
                "scan", self.client.scan, **kwargs
            )
            items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
        return items

    async def _query_all(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Query all pages for a key condition."""
        items: List[Dict[str, Any]] = []
        while True:
            response = await self._execute_with_circuit_breaker(
                "query", self.client.query, **kwargs
            )
            items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
        return items

    async def _update_record(
        self,
        table_name: str,
        pk: str,
        sk: str,
        updates: Dict[str, Any],
        *,
        condition_expression: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Parameterized SET update; returns ALL_NEW record or ``None``.

        All keys go through ExpressionAttributeNames/Values placeholders —
        caller input is never interpolated into the expression string.
        """
        set_parts = []
        names: Dict[str, str] = {}
        values: Dict[str, Any] = {}
        for key, value in updates.items():
            placeholder = _placeholder(key)
            # Avoid placeholder collisions for keys differing only in
            # non-alphanumeric characters.
            unique_placeholder = placeholder
            suffix = 0
            while unique_placeholder in names:
                suffix += 1
                unique_placeholder = f"{placeholder}{suffix}"
            names[unique_placeholder] = key
            values[f":u{len(values)}"] = self._serialize_value(value)
            set_parts.append(f"{unique_placeholder} = :u{len(values) - 1}")
        kwargs: Dict[str, Any] = {
            "TableName": table_name,
            "Key": {"PK": {"S": pk}, "SK": {"S": sk}},
            "UpdateExpression": "SET " + ", ".join(set_parts),
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values,
            "ReturnValues": "ALL_NEW",
        }
        if condition_expression:
            kwargs["ConditionExpression"] = condition_expression
            # Condition uses the static placeholders :cond_* added by callers
        try:
            response = await self._execute_with_circuit_breaker(
                "update_item", self.client.update_item, **kwargs
            )
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return None
            raise
        item = response.get("Attributes")
        if not item:
            return None
        return self._record_from_item(self._deserialize_item(item))
