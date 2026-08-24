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
        condition_names: Optional[Dict[str, str]] = None,
        condition_values: Optional[Dict[str, Any]] = None,
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
        if condition_names:
            names = {**names, **condition_names}
        if condition_values:
            values = {**values, **condition_values}
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


    # -- users ----------------------------------------------------------------

    async def _identifier_conflict(
        self,
        *,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        exclude_user_id: Optional[str] = None,
    ) -> Optional[str]:
        """Return the conflicting identifier, if any.

        Email uses the GSI1 query path; username/phone are documented
        scan fallbacks (no GSI projects those attributes).
        """
        table_name = self._get_table_name("users")
        if email:
            items = await self._query_all(
                TableName=table_name,
                IndexName="GSI1Index",
                KeyConditionExpression="GSI1PK = :pk",
                ExpressionAttributeValues={
                    ":pk": {"S": f"EMAIL#{str(email).lower()}"}
                },
            )
            for item in items:
                record = self._record_from_item(self._deserialize_item(item))
                if exclude_user_id and record.get("id") == exclude_user_id:
                    continue
                return str(email)
        if username:
            items = await self._scan_all(
                table_name,
                filter_expression="username_lowercase = :v",
                expression_attribute_values={
                    ":v": {"S": str(username).lower()}
                },
            )
            for item in items:
                record = self._record_from_item(self._deserialize_item(item))
                if exclude_user_id and record.get("id") == exclude_user_id:
                    continue
                return str(username)
        if phone:
            items = await self._scan_all(
                table_name,
                filter_expression="phone = :v",
                expression_attribute_values={":v": {"S": str(phone)}},
            )
            for item in items:
                record = self._record_from_item(self._deserialize_item(item))
                if exclude_user_id and record.get("id") == exclude_user_id:
                    continue
                return str(phone)
        return None

    async def create_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Create a user with unique email/username/phone enforcement."""
        if not isinstance(user, dict):
            raise ValueError("user must be a dict")
        record = dict(user)
        record.setdefault("id", _new_id())
        now = _utcnow()
        record.setdefault("created_at", _iso(now))
        record.setdefault("updated_at", _iso(now))
        record.setdefault("is_active", True)
        record.setdefault("mfa_enabled", False)
        record.setdefault("role", "user")
        conflict = await self._identifier_conflict(
            email=record.get("email"),
            username=record.get("username"),
            phone=record.get("phone"),
        )
        if conflict is not None:
            raise IntegrityError(
                f"A user with identifier {conflict!r} already exists"
            )
        item = dict(record)
        item["PK"] = f"USER#{record['id']}"
        item["SK"] = "PROFILE"
        if record.get("email"):
            item["GSI1PK"] = f"EMAIL#{str(record['email']).lower()}"
            item["GSI1SK"] = "PROFILE"
            item["email_lowercase"] = str(record["email"]).lower()
        if record.get("username"):
            item["username_lowercase"] = str(record["username"]).lower()
        await self._execute_with_circuit_breaker(
            "create_user",
            self.client.put_item,
            TableName=self._get_table_name("users"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        return await self._get_record(
            self._get_table_name("users"), f"USER#{user_id}"
        )

    async def get_user_by_identifier(
        self,
        *,
        username: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up one user; email via GSI1, username/phone via scan fallback."""
        table_name = self._get_table_name("users")
        if email:
            items = await self._query_all(
                TableName=table_name,
                IndexName="GSI1Index",
                KeyConditionExpression="GSI1PK = :pk",
                ExpressionAttributeValues={
                    ":pk": {"S": f"EMAIL#{str(email).lower()}"}
                },
            )
            if items:
                return self._record_from_item(self._deserialize_item(items[0]))
        # Documented scan fallback: no GSI projects username/phone.
        if username:
            items = await self._scan_all(
                table_name,
                filter_expression="username_lowercase = :v",
                expression_attribute_values={
                    ":v": {"S": str(username).lower()}
                },
            )
            if items:
                return self._record_from_item(self._deserialize_item(items[0]))
        if phone:
            items = await self._scan_all(
                table_name,
                filter_expression="phone = :v",
                expression_attribute_values={":v": {"S": str(phone)}},
            )
            if items:
                return self._record_from_item(self._deserialize_item(items[0]))
        return None

    async def update_user(
        self, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates or "created_at" in updates:
            raise ValueError("id and created_at are immutable")
        existing = await self.get_user_by_id(user_id)
        if existing is None:
            return None
        conflict = await self._identifier_conflict(
            email=updates.get("email", existing.get("email")),
            username=updates.get("username", existing.get("username")),
            phone=updates.get("phone", existing.get("phone")),
            exclude_user_id=user_id,
        )
        if conflict is not None:
            raise IntegrityError(
                f"A user with identifier {conflict!r} already exists"
            )
        set_fields = dict(updates)
        set_fields["updated_at"] = _iso(_utcnow())
        if "email" in updates and updates["email"]:
            set_fields["email_lowercase"] = str(updates["email"]).lower()
            set_fields["GSI1PK"] = f"EMAIL#{str(updates['email']).lower()}"
            set_fields["GSI1SK"] = "PROFILE"
        if "username" in updates and updates["username"]:
            set_fields["username_lowercase"] = str(updates["username"]).lower()
        return await self._update_record(
            self._get_table_name("users"),
            f"USER#{user_id}",
            "PROFILE",
            set_fields,
            condition_expression="attribute_exists(PK)",
        )

    async def delete_user(self, user_id: str) -> bool:
        try:
            await self._execute_with_circuit_breaker(
                "delete_user",
                self.client.delete_item,
                TableName=self._get_table_name("users"),
                Key={
                    "PK": {"S": f"USER#{user_id}"},
                    "SK": {"S": "PROFILE"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def list_users(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        search: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Documented scan fallback; returns ``(rows, total_matching)``."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        items = await self._scan_all(self._get_table_name("users"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        if search:
            needle = search.lower()
            records = [
                record
                for record in records
                if needle
                in " ".join(
                    str(record.get(field, ""))
                    for field in ("username", "email")
                ).lower()
            ]
        if filters:
            for key, expected in filters.items():
                records = [
                    record
                    for record in records
                    if record.get(key) == expected
                ]
        records.sort(key=lambda r: str(r.get("created_at", "")))
        return records[offset : offset + limit], len(records)

    async def count_users(
        self,
        *,
        active_only: bool = False,
        mfa_enabled: Optional[bool] = None,
        created_since: Optional[datetime] = None,
    ) -> int:
        """Documented scan fallback."""
        items = await self._scan_all(self._get_table_name("users"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        since_iso = _iso(created_since) if created_since is not None else None
        count = 0
        for record in records:
            if active_only and not record.get("is_active"):
                continue
            if mfa_enabled is not None and bool(
                record.get("mfa_enabled")
            ) != mfa_enabled:
                continue
            if since_iso is not None and str(
                record.get("created_at", "")
            ) < since_iso:
                continue
            count += 1
        return count

    # -- sessions ---------------------------------------------------------------

    async def save_session(self, session: Dict[str, Any]) -> None:
        """Insert or replace a session document."""
        if not isinstance(session, dict):
            raise ValueError("session must be a dict")
        if not session.get("user_id"):
            raise ValueError("session.user_id is required")
        record = dict(session)
        record.setdefault("id", _new_id())
        record.setdefault("status", "active")
        record.setdefault("created_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"SESSION#{record['id']}"
        item["SK"] = "PROFILE"
        item["GSI1PK"] = f"USER#{record['user_id']}"
        item["GSI1SK"] = f"SESSION#{record['id']}"
        await self._execute_with_circuit_breaker(
            "save_session",
            self.client.put_item,
            TableName=self._get_table_name("sessions"),
            Item=self._serialize_item(item),
        )

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return await self._get_record(
            self._get_table_name("sessions"), f"SESSION#{session_id}"
        )

    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Query the user's sessions; only ``status == 'active'`` returned."""
        items = await self._query_all(
            TableName=self._get_table_name("sessions"),
            IndexName="GSI1Index",
            KeyConditionExpression=(
                "GSI1PK = :pk AND begins_with(GSI1SK, :sk_prefix)"
            ),
            ExpressionAttributeValues={
                ":pk": {"S": f"USER#{user_id}"},
                ":sk_prefix": {"S": "SESSION#"},
            },
        )
        sessions = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        return [s for s in sessions if s.get("status") == "active"]

    async def revoke_session(self, session_id: str) -> bool:
        """Atomic conditional flip: only the first revoke wins."""
        try:
            await self._execute_with_circuit_breaker(
                "revoke_session",
                self.client.update_item,
                TableName=self._get_table_name("sessions"),
                Key={
                    "PK": {"S": f"SESSION#{session_id}"},
                    "SK": {"S": "PROFILE"},
                },
                UpdateExpression=(
                    "SET #status = :revoked, #revoked_at = :revoked_at"
                ),
                ExpressionAttributeNames={
                    "#status": "status",
                    "#revoked_at": "revoked_at",
                },
                ExpressionAttributeValues={
                    ":revoked": {"S": "revoked"},
                    ":revoked_at": {"S": _iso(_utcnow())},
                    ":active": {"S": "active"},
                },
                ConditionExpression=(
                    "attribute_exists(PK) AND #status = :active"
                ),
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        revoked = 0
        for session in await self.get_active_sessions(user_id):
            if await self.revoke_session(session["id"]):
                revoked += 1
        return revoked

    # -- organizations -------------------------------------------------------

    async def create_organization(self, org: Dict[str, Any]) -> Dict[str, Any]:
        """Create an organization with a unique slug."""
        if not isinstance(org, dict):
            raise ValueError("org must be a dict")
        record = dict(org)
        if not record.get("name"):
            raise ValueError("org.name is required")
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record["slug"] = str(record["slug"]).lower()
        now = _utcnow()
        record.setdefault("created_at", _iso(now))
        record.setdefault("updated_at", _iso(now))
        if await self.get_organization_by_slug(record["slug"]) is not None:
            raise IntegrityError(
                f"An organization with slug {record['slug']!r} already exists"
            )
        item = dict(record)
        item["PK"] = f"ORG#{record['id']}"
        item["SK"] = "PROFILE"
        item["GSI1PK"] = f"SLUG#{record['slug']}"
        item["GSI1SK"] = "PROFILE"
        await self._execute_with_circuit_breaker(
            "create_organization",
            self.client.put_item,
            TableName=self._get_table_name("organizations"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        return await self._get_record(
            self._get_table_name("organizations"), f"ORG#{org_id}"
        )

    async def get_organization_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        items = await self._query_all(
            TableName=self._get_table_name("organizations"),
            IndexName="GSI1Index",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={
                ":pk": {"S": f"SLUG#{str(slug).lower()}"}
            },
        )
        if not items:
            return None
        return self._record_from_item(self._deserialize_item(items[0]))

    async def update_organization(
        self, org_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates:
            raise ValueError("id is immutable")
        set_fields = dict(updates)
        new_slug = updates.get("slug")
        if new_slug is not None:
            candidate = str(new_slug).lower()
            owner = await self.get_organization_by_slug(candidate)
            if owner is not None and owner.get("id") != org_id:
                raise IntegrityError(
                    f"An organization with slug {candidate!r} already exists"
                )
            set_fields["slug"] = candidate
            set_fields["GSI1PK"] = f"SLUG#{candidate}"
            set_fields["GSI1SK"] = "PROFILE"
        set_fields["updated_at"] = _iso(_utcnow())
        return await self._update_record(
            self._get_table_name("organizations"),
            f"ORG#{org_id}",
            "PROFILE",
            set_fields,
            condition_expression="attribute_exists(PK)",
        )

    async def delete_organization(self, org_id: str) -> bool:
        """Delete an organization and its member/invitation links."""
        members_table = self._get_table_name("org_members")
        member_items = await self._query_all(
            TableName=members_table,
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"ORG#{org_id}"}},
        )
        for item in member_items:
            key = {
                "PK": item["PK"],
                "SK": item["SK"],
            }
            await self._execute_with_circuit_breaker(
                "delete_org_member",
                self.client.delete_item,
                TableName=members_table,
                Key=key,
            )
        # Documented scan fallback for the invitation cascade.
        invitation_items = await self._scan_all(
            self._get_table_name("invitations"),
            filter_expression="org_id = :org",
            expression_attribute_values={":org": {"S": org_id}},
        )
        for item in invitation_items:
            await self._execute_with_circuit_breaker(
                "delete_invitation_cascade",
                self.client.delete_item,
                TableName=self._get_table_name("invitations"),
                Key={"PK": item["PK"], "SK": item["SK"]},
            )
        try:
            await self._execute_with_circuit_breaker(
                "delete_organization",
                self.client.delete_item,
                TableName=self._get_table_name("organizations"),
                Key={"PK": {"S": f"ORG#{org_id}"}, "SK": {"S": "PROFILE"}},
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def list_organizations(
        self, *, limit: int = 50, offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Documented scan fallback; returns ``(rows, total)``."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        items = await self._scan_all(self._get_table_name("organizations"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        records.sort(key=lambda r: str(r.get("created_at", "")))
        return records[offset : offset + limit], len(records)

    async def add_org_member(self, org_id: str, member: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member to an organization."""
        if not isinstance(member, dict) or not member.get("user_id"):
            raise ValueError("member must be a dict with a user_id")
        if await self.get_organization(org_id) is None:
            raise IntegrityError(f"Organization {org_id!r} does not exist")
        record = dict(member)
        record["user_id"] = str(record["user_id"])
        record["org_id"] = org_id
        record.setdefault("role", "member")
        record.setdefault("added_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"ORG#{org_id}"
        item["SK"] = f"MEMBER#{record['user_id']}"
        item["GSI1PK"] = f"USER#{record['user_id']}"
        item["GSI1SK"] = f"ORG#{org_id}"
        try:
            await self._execute_with_circuit_breaker(
                "add_org_member",
                self.client.put_item,
                TableName=self._get_table_name("org_members"),
                Item=self._serialize_item(item),
                ConditionExpression="attribute_not_exists(PK)",
            )
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                raise IntegrityError(
                    f"User {record['user_id']!r} is already a member of "
                    f"{org_id!r}"
                ) from exc
            raise
        return dict(record)

    async def get_org_members(self, org_id: str) -> List[Dict[str, Any]]:
        items = await self._query_all(
            TableName=self._get_table_name("org_members"),
            KeyConditionExpression=(
                "PK = :pk AND begins_with(SK, :sk_prefix)"
            ),
            ExpressionAttributeValues={
                ":pk": {"S": f"ORG#{org_id}"},
                ":sk_prefix": {"S": "MEMBER#"},
            },
        )
        members = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        members.sort(key=lambda r: str(r.get("added_at", "")))
        return members

    async def update_org_member(
        self, org_id: str, user_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "user_id" in updates:
            raise ValueError("user_id is immutable")
        return await self._update_record(
            self._get_table_name("org_members"),
            f"ORG#{org_id}",
            f"MEMBER#{user_id}",
            dict(updates),
            condition_expression="attribute_exists(PK)",
        )

    async def remove_org_member(self, org_id: str, user_id: str) -> bool:
        try:
            await self._execute_with_circuit_breaker(
                "remove_org_member",
                self.client.delete_item,
                TableName=self._get_table_name("org_members"),
                Key={
                    "PK": {"S": f"ORG#{org_id}"},
                    "SK": {"S": f"MEMBER#{user_id}"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def create_invitation(self, invitation: Dict[str, Any]) -> Dict[str, Any]:
        """Create an org invitation (token generated when absent)."""
        if not isinstance(invitation, dict) or not invitation.get("org_id"):
            raise ValueError("invitation must be a dict with an org_id")
        if await self.get_organization(invitation["org_id"]) is None:
            raise IntegrityError(
                f"Organization {invitation['org_id']!r} does not exist"
            )
        record = dict(invitation)
        record.setdefault("id", _new_id())
        record.setdefault("token", secrets.token_urlsafe(32))
        record.setdefault("status", "pending")
        record.setdefault("created_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"INVITE#{record['id']}"
        item["SK"] = "PROFILE"
        await self._execute_with_circuit_breaker(
            "create_invitation",
            self.client.put_item,
            TableName=self._get_table_name("invitations"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def get_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Documented scan fallback (no GSI on token)."""
        items = await self._scan_all(
            self._get_table_name("invitations"),
            filter_expression="token = :token",
            expression_attribute_values={":token": {"S": token}},
        )
        if not items:
            return None
        return self._record_from_item(self._deserialize_item(items[0]))

    async def get_pending_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        """Documented scan fallback (no GSI on org/status)."""
        items = await self._scan_all(
            self._get_table_name("invitations"),
            filter_expression="org_id = :org AND #status = :pending",
            expression_attribute_values={
                ":org": {"S": org_id},
                ":pending": {"S": "pending"},
            },
            expression_attribute_names={"#status": "status"},
        )
        invitations = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        invitations.sort(key=lambda r: str(r.get("created_at", "")))
        return invitations

    async def delete_invitation(self, invitation_id: str) -> bool:
        try:
            await self._execute_with_circuit_breaker(
                "delete_invitation",
                self.client.delete_item,
                TableName=self._get_table_name("invitations"),
                Key={
                    "PK": {"S": f"INVITE#{invitation_id}"},
                    "SK": {"S": "PROFILE"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise


    # -- audit log --------------------------------------------------------------

    @staticmethod
    def _audit_checksum(payload: Dict[str, Any], previous_checksum: str) -> str:
        """sha256 over canonical JSON incl. ``previous_checksum`` (hash chain)."""
        return hashlib.sha256(
            _canonical_json({**payload, "previous_checksum": previous_checksum})
        ).hexdigest()

    async def _last_audit_state(self) -> Tuple[str, int]:
        """Documented scan fallback: find the chain tail (max sequence)."""
        items = await self._scan_all(self._get_table_name("audit_events"))
        best: Optional[Dict[str, Any]] = None
        for item in items:
            record = self._record_from_item(self._deserialize_item(item))
            if best is None or int(record.get("sequence", 0)) > int(
                best.get("sequence", 0)
            ):
                best = record
        if best is None:
            return GENESIS_CHECKSUM, 0
        return best["checksum"], int(best["sequence"])

    async def _append_audit_event(
        self, event: Dict[str, Any], previous_checksum: str, sequence: int
    ) -> Dict[str, Any]:
        if not isinstance(event, dict):
            raise ValueError("event must be a dict")
        record = dict(event)
        event_id = record.setdefault("id", _new_id())
        timestamp = record.get("timestamp")
        record["timestamp"] = (
            _iso(timestamp) if isinstance(timestamp, datetime) else
            timestamp if isinstance(timestamp, str) and timestamp else
            _iso(_utcnow())
        )
        payload = {
            key: value
            for key, value in record.items()
            if key not in _AUDIT_DB_ASSIGNED_FIELDS and key != "previous_checksum"
        }
        payload = json.loads(json.dumps(payload, default=str))
        checksum = self._audit_checksum(payload, previous_checksum)
        doc = {
            **payload,
            "id": event_id,
            "sequence": sequence,
            "checksum": checksum,
            "previous_checksum": previous_checksum,
        }
        item: Dict[str, Any] = {
            # Event id in the PK: no same-second collisions.
            "PK": f"AUDIT#{event_id}",
            "SK": "PROFILE",
            "GSI1PK": f"ACTOR#{payload.get('actor', 'unknown')}",
            "GSI1SK": record["timestamp"],
            "GSI2PK": f"EVENT#{payload.get('event_type', 'unknown')}",
            "GSI2SK": record["timestamp"],
            "id": event_id,
            "sequence": sequence,
            "timestamp": record["timestamp"],
            "checksum": checksum,
            "previous_checksum": previous_checksum,
            "data": payload,
        }
        await self._execute_with_circuit_breaker(
            "save_audit_event",
            self.client.put_item,
            TableName=self._get_table_name("audit_events"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return doc

    async def save_audit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Append one event to the hash chain."""
        async with self._audit_lock:
            previous, sequence = await self._last_audit_state()
            return await self._append_audit_event(
                event, previous, sequence + 1
            )

    async def save_audit_events(self, events: List[Dict[str, Any]]) -> int:
        """Append events in order."""
        if not isinstance(events, list):
            raise ValueError("events must be a list")
        async with self._audit_lock:
            previous, sequence = await self._last_audit_state()
            for event in events:
                sequence += 1
                doc = await self._append_audit_event(event, previous, sequence)
                previous = doc["checksum"]
        return len(events)

    async def _all_audit_records(self) -> List[Dict[str, Any]]:
        items = await self._scan_all(self._get_table_name("audit_events"))
        records = []
        for item in items:
            raw = self._record_from_item(self._deserialize_item(item))
            data = dict(raw.get("data") or {})
            data.update(
                {
                    "id": raw.get("id"),
                    "sequence": raw.get("sequence"),
                    "checksum": raw.get("checksum"),
                    "previous_checksum": raw.get("previous_checksum"),
                }
            )
            records.append(data)
        return records

    async def search_audit_events(
        self,
        *,
        event_types: Optional[List[str]] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Actor/single-type paths use GSIs; otherwise documented scan fallback."""
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be non-negative")
        table_name = self._get_table_name("audit_events")
        items: List[Dict[str, Any]] = []
        if actor is not None:
            key_condition = "GSI1PK = :pk"
            values: Dict[str, Any] = {":pk": {"S": f"ACTOR#{actor}"}}
            if start is not None and end is not None:
                key_condition += " AND GSI1SK BETWEEN :start AND :end"
                values[":start"] = {"S": _iso(start)}
                values[":end"] = {"S": _iso(end)}
            elif start is not None:
                key_condition += " AND GSI1SK >= :start"
                values[":start"] = {"S": _iso(start)}
            elif end is not None:
                key_condition += " AND GSI1SK <= :end"
                values[":end"] = {"S": _iso(end)}
            items = await self._query_all(
                TableName=table_name,
                IndexName="GSI1Index",
                KeyConditionExpression=key_condition,
                ExpressionAttributeValues=values,
            )
        elif event_types and len(event_types) == 1:
            key_condition = "GSI2PK = :pk"
            values = {":pk": {"S": f"EVENT#{event_types[0]}"} }
            if start is not None and end is not None:
                key_condition += " AND GSI2SK BETWEEN :start AND :end"
                values[":start"] = {"S": _iso(start)}
                values[":end"] = {"S": _iso(end)}
            elif start is not None:
                key_condition += " AND GSI2SK >= :start"
                values[":start"] = {"S": _iso(start)}
            elif end is not None:
                key_condition += " AND GSI2SK <= :end"
                values[":end"] = {"S": _iso(end)}
            items = await self._query_all(
                TableName=table_name,
                IndexName="GSI2Index",
                KeyConditionExpression=key_condition,
                ExpressionAttributeValues=values,
            )
        else:
            # Documented scan fallback (multi-type / target-only / no filter).
            items = await self._scan_all(table_name)

        type_filter = set(event_types) if event_types else None
        start_iso = _iso(start) if start is not None else None
        end_iso = _iso(end) if end is not None else None
        matching: List[Dict[str, Any]] = []
        for item in items:
            raw = self._record_from_item(self._deserialize_item(item))
            data = dict(raw.get("data") or {})
            if type_filter is not None and data.get("event_type") not in type_filter:
                continue
            if actor is not None and data.get("actor") != actor:
                continue
            if target is not None and data.get("target") != target:
                continue
            timestamp = raw.get("timestamp", "")
            if start_iso is not None and timestamp < start_iso:
                continue
            if end_iso is not None and timestamp > end_iso:
                continue
            data.update(
                {
                    "id": raw.get("id"),
                    "sequence": raw.get("sequence"),
                    "checksum": raw.get("checksum"),
                    "previous_checksum": raw.get("previous_checksum"),
                }
            )
            matching.append(data)
        matching.sort(key=lambda r: str(r.get("timestamp", "")), reverse=True)
        return matching[offset : offset + limit], len(matching)

    async def get_audit_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        raw = await self._get_record(
            self._get_table_name("audit_events"), f"AUDIT#{event_id}"
        )
        if raw is None:
            return None
        data = dict(raw.get("data") or {})
        data.update(
            {
                "id": raw.get("id"),
                "sequence": raw.get("sequence"),
                "checksum": raw.get("checksum"),
                "previous_checksum": raw.get("previous_checksum"),
            }
        )
        return data

    async def delete_audit_events_before(self, ts: datetime) -> int:
        """Documented scan fallback; returns the count deleted."""
        cutoff = _iso(ts)
        records = await self._all_audit_records()
        deleted = 0
        for record in records:
            if str(record.get("timestamp", "")) >= cutoff:
                continue
            await self._execute_with_circuit_breaker(
                "delete_audit_event",
                self.client.delete_item,
                TableName=self._get_table_name("audit_events"),
                Key={
                    "PK": {"S": f"AUDIT#{record['id']}"},
                    "SK": {"S": "PROFILE"},
                },
            )
            deleted += 1
        return deleted

    async def get_audit_statistics(
        self, *, since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Documented scan fallback."""
        records = await self._all_audit_records()
        since_iso = _iso(since) if since is not None else None
        total = 0
        by_type: Dict[str, int] = {}
        by_actor: Dict[str, int] = {}
        first_at: Optional[str] = None
        last_at: Optional[str] = None
        for record in records:
            timestamp = str(record.get("timestamp", ""))
            if since_iso is not None and timestamp < since_iso:
                continue
            total += 1
            type_key = str(record.get("event_type", "unknown"))
            actor_key = str(record.get("actor", "unknown"))
            by_type[type_key] = by_type.get(type_key, 0) + 1
            by_actor[actor_key] = by_actor.get(actor_key, 0) + 1
            if first_at is None or timestamp < first_at:
                first_at = timestamp
            if last_at is None or timestamp > last_at:
                last_at = timestamp
        return {
            "total_events": total,
            "events_by_type": by_type,
            "events_by_actor": by_actor,
            "first_event_at": (
                datetime.fromisoformat(first_at) if first_at else None
            ),
            "last_event_at": (
                datetime.fromisoformat(last_at) if last_at else None
            ),
        }

    async def get_audit_time_series(
        self, *, since: datetime, bucket_seconds: int
    ) -> List[Dict[str, Any]]:
        """Documented scan fallback; bucketed counts from ``since`` to now."""
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        start = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        now = _utcnow()
        if start > now:
            return []
        records = await self._all_audit_records()
        bucket_count = int((now - start).total_seconds() // bucket_seconds) + 1
        buckets = [
            {
                "bucket_start": datetime.fromtimestamp(
                    start.timestamp() + i * bucket_seconds, tz=timezone.utc
                ),
                "count": 0,
            }
            for i in range(bucket_count)
        ]
        for record in records:
            try:
                when = datetime.fromisoformat(str(record.get("timestamp")))
            except ValueError:
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when < start or when > now:
                continue
            index = int((when - start).total_seconds() // bucket_seconds)
            buckets[min(index, bucket_count - 1)]["count"] += 1
        return buckets


    # -- webhooks ----------------------------------------------------------------

    async def save_webhook_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Create a webhook endpoint record."""
        if not isinstance(endpoint, dict) or not endpoint.get("url"):
            raise ValueError("endpoint must be a dict with a url")
        record = dict(endpoint)
        record.setdefault("id", _new_id())
        record.setdefault("events", [])
        record.setdefault("enabled", True)
        record.setdefault("created_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"WEBHOOK#{record['id']}"
        item["SK"] = "PROFILE"
        await self._execute_with_circuit_breaker(
            "save_webhook_endpoint",
            self.client.put_item,
            TableName=self._get_table_name("webhook_endpoints"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def get_webhook_endpoint(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        return await self._get_record(
            self._get_table_name("webhook_endpoints"), f"WEBHOOK#{endpoint_id}"
        )

    async def list_webhook_endpoints(self) -> List[Dict[str, Any]]:
        """Documented scan fallback."""
        items = await self._scan_all(self._get_table_name("webhook_endpoints"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        records.sort(key=lambda r: str(r.get("created_at", "")))
        return records

    async def update_webhook_endpoint(
        self, endpoint_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        if "id" in updates:
            raise ValueError("id is immutable")
        set_fields = dict(updates)
        set_fields["updated_at"] = _iso(_utcnow())
        return await self._update_record(
            self._get_table_name("webhook_endpoints"),
            f"WEBHOOK#{endpoint_id}",
            "PROFILE",
            set_fields,
            condition_expression="attribute_exists(PK)",
        )

    async def delete_webhook_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint and its delivery history."""
        delivery_items = await self._query_all(
            TableName=self._get_table_name("webhook_deliveries"),
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={
                ":pk": {"S": f"DELIVERY#{endpoint_id}"}
            },
        )
        for item in delivery_items:
            await self._execute_with_circuit_breaker(
                "delete_webhook_delivery",
                self.client.delete_item,
                TableName=self._get_table_name("webhook_deliveries"),
                Key={"PK": item["PK"], "SK": item["SK"]},
            )
        try:
            await self._execute_with_circuit_breaker(
                "delete_webhook_endpoint",
                self.client.delete_item,
                TableName=self._get_table_name("webhook_endpoints"),
                Key={
                    "PK": {"S": f"WEBHOOK#{endpoint_id}"},
                    "SK": {"S": "PROFILE"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def save_webhook_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        """Record a delivery attempt for an endpoint."""
        if not isinstance(delivery, dict) or not delivery.get("endpoint_id"):
            raise ValueError("delivery must be a dict with an endpoint_id")
        if await self.get_webhook_endpoint(delivery["endpoint_id"]) is None:
            raise IntegrityError(
                f"Webhook endpoint {delivery['endpoint_id']!r} does not exist"
            )
        record = dict(delivery)
        record.setdefault("id", _new_id())
        record.setdefault("created_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"DELIVERY#{record['endpoint_id']}"
        item["SK"] = f"DELIVERY#{record['created_at']}#{record['id']}"
        await self._execute_with_circuit_breaker(
            "save_webhook_delivery",
            self.client.put_item,
            TableName=self._get_table_name("webhook_deliveries"),
            Item=self._serialize_item(item),
        )
        return dict(record)

    async def get_webhook_deliveries(
        self, endpoint_id: str, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        items = await self._query_all(
            TableName=self._get_table_name("webhook_deliveries"),
            KeyConditionExpression=(
                "PK = :pk AND begins_with(SK, :sk_prefix)"
            ),
            ExpressionAttributeValues={
                ":pk": {"S": f"DELIVERY#{endpoint_id}"},
                ":sk_prefix": {"S": "DELIVERY#"},
            },
            ScanIndexForward=False,
            Limit=limit,
        )
        return [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]

    # -- RBAC ---------------------------------------------------------------------

    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a role (unique name; documented scan check)."""
        if not isinstance(role, dict) or not role.get("name"):
            raise ValueError("role must be a dict with a name")
        role_id = role.get("id")
        duplicate_items = await self._scan_all(
            self._get_table_name("roles"),
            filter_expression="#name = :name",
            expression_attribute_values={":name": {"S": role["name"]}},
            expression_attribute_names={"#name": "name"},
        )
        for item in duplicate_items:
            record = self._record_from_item(self._deserialize_item(item))
            if role_id and record.get("id") == role_id:
                continue
            raise IntegrityError(
                f"A role named {role['name']!r} already exists"
            )
        record = dict(role)
        existing = (
            await self.get_role(role_id) if role_id else None
        )
        if existing is None:
            record.setdefault("id", _new_id())
            record.setdefault("created_at", _iso(_utcnow()))
        else:
            record.setdefault("created_at", existing.get("created_at"))
        record.setdefault("permissions", [])
        record["updated_at"] = _iso(_utcnow())
        item = dict(record)
        item["PK"] = f"ROLE#{record['id']}"
        item["SK"] = "PROFILE"
        await self._execute_with_circuit_breaker(
            "save_role",
            self.client.put_item,
            TableName=self._get_table_name("roles"),
            Item=self._serialize_item(item),
        )
        return dict(record)

    async def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        return await self._get_record(
            self._get_table_name("roles"), f"ROLE#{role_id}"
        )

    async def list_roles(self) -> List[Dict[str, Any]]:
        """Documented scan fallback."""
        items = await self._scan_all(self._get_table_name("roles"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        records.sort(key=lambda r: str(r.get("created_at", "")))
        return records

    async def delete_role(self, role_id: str) -> bool:
        # Documented scan fallback for the assignment existence check.
        assignment_items = await self._scan_all(
            self._get_table_name("role_assignments"),
            filter_expression="role_id = :role",
            expression_attribute_values={":role": {"S": role_id}},
        )
        if assignment_items:
            raise IntegrityError(
                f"Role {role_id!r} still has assignments; remove them first"
            )
        try:
            await self._execute_with_circuit_breaker(
                "delete_role",
                self.client.delete_item,
                TableName=self._get_table_name("roles"),
                Key={
                    "PK": {"S": f"ROLE#{role_id}"},
                    "SK": {"S": "PROFILE"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def save_role_assignment(self, assignment: Dict[str, Any]) -> Dict[str, Any]:
        """Create a role assignment (role must exist)."""
        if not isinstance(assignment, dict):
            raise ValueError("assignment must be a dict")
        if not assignment.get("user_id") or not assignment.get("role_id"):
            raise ValueError("assignment requires user_id and role_id")
        if await self.get_role(assignment["role_id"]) is None:
            raise IntegrityError(
                f"Role {assignment['role_id']!r} does not exist"
            )
        record = dict(assignment)
        record.setdefault("id", _new_id())
        record.setdefault("created_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"ASSIGN#{record['id']}"
        item["SK"] = "PROFILE"
        item["GSI1PK"] = f"USER#{record['user_id']}"
        item["GSI1SK"] = f"ASSIGN#{record['id']}"
        await self._execute_with_circuit_breaker(
            "save_role_assignment",
            self.client.put_item,
            TableName=self._get_table_name("role_assignments"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def query_role_assignments(
        self,
        *,
        user_id: Optional[str] = None,
        role_id: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Documented scan fallback; provided filters combine with AND."""
        items = await self._scan_all(self._get_table_name("role_assignments"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        if user_id is not None:
            records = [r for r in records if r.get("user_id") == user_id]
        if role_id is not None:
            records = [r for r in records if r.get("role_id") == role_id]
        if scope_type is not None:
            records = [r for r in records if r.get("scope_type") == scope_type]
        if scope_id is not None:
            records = [r for r in records if r.get("scope_id") == scope_id]
        records.sort(key=lambda r: str(r.get("created_at", "")))
        return records

    async def delete_role_assignment(self, assignment_id: str) -> bool:
        try:
            await self._execute_with_circuit_breaker(
                "delete_role_assignment",
                self.client.delete_item,
                TableName=self._get_table_name("role_assignments"),
                Key={
                    "PK": {"S": f"ASSIGN#{assignment_id}"},
                    "SK": {"S": "PROFILE"},
                },
                ConditionExpression="attribute_exists(PK)",
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    # -- api keys --------------------------------------------------------------------

    async def save_api_key(self, key_record: Dict[str, Any]) -> Dict[str, Any]:
        """Store an API key record; only the sha256 hash is persisted."""
        if not isinstance(key_record, dict):
            raise ValueError("key_record must be a dict")
        if key_record.get("key") or key_record.get("api_key"):
            raise ValueError(
                "plaintext API keys must never be stored; pass key_hash (sha256)"
            )
        key_hash = key_record.get("key_hash")
        if not key_hash or not isinstance(key_hash, str):
            raise ValueError("key_record.key_hash (sha256 hex) is required")
        existing = await self.get_api_key_by_hash(key_hash)
        if existing is not None and existing.get("id") != key_record.get("id"):
            raise IntegrityError("An API key with this hash already exists")
        record = dict(key_record)
        record.setdefault("id", _new_id())
        record.setdefault("revoked", False)
        record.setdefault("created_at", _iso(_utcnow()))
        item = dict(record)
        item["PK"] = f"APIKEY#{record['id']}"
        item["SK"] = "PROFILE"
        item["GSI1PK"] = f"HASH#{key_hash}"
        item["GSI1SK"] = "PROFILE"
        await self._execute_with_circuit_breaker(
            "save_api_key",
            self.client.put_item,
            TableName=self._get_table_name("api_keys"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        items = await self._query_all(
            TableName=self._get_table_name("api_keys"),
            IndexName="GSI1Index",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"HASH#{key_hash}"}},
        )
        if not items:
            return None
        return self._record_from_item(self._deserialize_item(items[0]))

    async def list_api_keys(self) -> List[Dict[str, Any]]:
        """Documented scan fallback."""
        items = await self._scan_all(self._get_table_name("api_keys"))
        records = [
            self._record_from_item(self._deserialize_item(item))
            for item in items
        ]
        records.sort(key=lambda r: str(r.get("created_at", "")))
        return records

    async def revoke_api_key(self, key_id: str) -> bool:
        result = await self._update_record(
            self._get_table_name("api_keys"),
            f"APIKEY#{key_id}",
            "PROFILE",
            {"revoked": True, "revoked_at": _iso(_utcnow())},
            condition_expression="attribute_exists(PK)",
        )
        return result is not None

    # -- settings -----------------------------------------------------------------------

    async def get_setting(self, key: str) -> Any:
        record = await self._get_record(
            self._get_table_name("settings"), f"SETTING#{key}"
        )
        if record is None:
            return None
        return record.get("value")

    async def set_setting(self, key: str, value: Any) -> None:
        if not key or not isinstance(key, str):
            raise ValueError("setting key must be a non-empty string")
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"setting value for {key!r} must be JSON-serializable"
            ) from exc
        item = {
            "PK": f"SETTING#{key}",
            "SK": "PROFILE",
            "key": key,
            "value": value,
        }
        await self._execute_with_circuit_breaker(
            "set_setting",
            self.client.put_item,
            TableName=self._get_table_name("settings"),
            Item=self._serialize_item(item),
        )


    # -- SAML ---------------------------------------------------------------------------

    async def save_saml_request(
        self, request_id: str, data: Dict[str, Any], *, ttl_seconds: int
    ) -> None:
        """Store transient SAML request state with a TTL."""
        if not request_id or not isinstance(request_id, str):
            raise ValueError("request_id must be a non-empty string")
        if not isinstance(data, dict):
            raise ValueError("data must be a dict")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        item = {
            "PK": f"SAML_REQ#{request_id}",
            "SK": "PROFILE",
            "data": dict(data),
            "expires_at": time.time() + ttl_seconds,
        }
        await self._execute_with_circuit_breaker(
            "save_saml_request",
            self.client.put_item,
            TableName=self._get_table_name("saml_requests"),
            Item=self._serialize_item(item),
        )

    async def consume_saml_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Atomic conditional delete (attribute_exists + expiry, one op)."""
        try:
            response = await self._execute_with_circuit_breaker(
                "consume_saml_request",
                self.client.delete_item,
                TableName=self._get_table_name("saml_requests"),
                Key={
                    "PK": {"S": f"SAML_REQ#{request_id}"},
                    "SK": {"S": "PROFILE"},
                },
                ConditionExpression="attribute_exists(PK) AND expires_at > :now",
                ExpressionAttributeValues={":now": {"N": str(time.time())}},
                ReturnValues="ALL_OLD",
            )
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return None
            raise
        item = response.get("Attributes")
        if not item:
            return None
        record = self._record_from_item(self._deserialize_item(item))
        return record.get("data")

    async def save_saml_response_id(self, response_id: str, *, ttl_seconds: int) -> None:
        """Record a consumed ResponseID for replay protection."""
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        item = {
            "PK": f"SAML_RESP#{response_id}",
            "SK": "PROFILE",
            "expires_at": time.time() + ttl_seconds,
        }
        await self._execute_with_circuit_breaker(
            "save_saml_response_id",
            self.client.put_item,
            TableName=self._get_table_name("saml_response_ids"),
            Item=self._serialize_item(item),
        )

    async def check_and_record_saml_response_id(self, response_id: str) -> bool:
        """Atomic conditional put: fresh (and recorded) ``True``, replay ``False``."""
        if not response_id or not isinstance(response_id, str):
            raise ValueError("response_id must be a non-empty string")
        item = {
            "PK": f"SAML_RESP#{response_id}",
            "SK": "PROFILE",
            "recorded_at": _iso(_utcnow()),
            # No expires_at: persistent ledger entries never replay.
        }
        try:
            await self._execute_with_circuit_breaker(
                "check_and_record_saml_response_id",
                self.client.put_item,
                TableName=self._get_table_name("saml_response_ids"),
                Item=self._serialize_item(item),
                ConditionExpression=(
                    "attribute_not_exists(PK) OR expires_at < :now"
                ),
                ExpressionAttributeValues={":now": {"N": str(time.time())}},
            )
            return True
        except Exception as exc:
            if self._is_conditional_check_failed(exc):
                return False
            raise

    async def save_saml_user_mapping(
        self, name_id: str, sp_entity_id: str, user_id: str
    ) -> None:
        if not name_id or not sp_entity_id or not user_id:
            raise ValueError("name_id, sp_entity_id and user_id are required")
        item = {
            "PK": f"SAML_MAP#{name_id}\x1f{sp_entity_id}",
            "SK": "PROFILE",
            "name_id": name_id,
            "sp_entity_id": sp_entity_id,
            "user_id": user_id,
        }
        await self._execute_with_circuit_breaker(
            "save_saml_user_mapping",
            self.client.put_item,
            TableName=self._get_table_name("saml_user_mappings"),
            Item=self._serialize_item(item),
        )

    async def get_saml_user_mapping(
        self, name_id: str, sp_entity_id: str
    ) -> Optional[str]:
        record = await self._get_record(
            self._get_table_name("saml_user_mappings"),
            f"SAML_MAP#{name_id}\x1f{sp_entity_id}",
        )
        return record.get("user_id") if record else None

    # -- OIDC -----------------------------------------------------------------------------

    async def save_oidc_provider(self, provider: Dict[str, Any]) -> Dict[str, Any]:
        """Create an OIDC provider with unique issuer and slug."""
        if not isinstance(provider, dict):
            raise ValueError("provider must be a dict")
        if not provider.get("issuer") or not provider.get("name"):
            raise ValueError("provider requires issuer and name")
        record = dict(provider)
        record.setdefault("id", _new_id())
        record.setdefault("slug", _slugify(str(record["name"])))
        record["slug"] = str(record["slug"]).lower()
        record["issuer"] = str(record["issuer"])
        record.setdefault("enabled", True)
        record.setdefault("created_at", _iso(_utcnow()))
        if await self._get_record(
            self._get_table_name("oidc_providers"), f"OIDC#{record['issuer']}"
        ) is not None:
            raise IntegrityError(
                f"An OIDC provider with issuer {record['issuer']!r} "
                "already exists"
            )
        # Documented scan fallback for slug uniqueness.
        slug_items = await self._scan_all(
            self._get_table_name("oidc_providers"),
            filter_expression="slug = :slug",
            expression_attribute_values={":slug": {"S": record["slug"]}},
        )
        if slug_items:
            raise IntegrityError(
                f"An OIDC provider with slug {record['slug']!r} already exists"
            )
        item = dict(record)
        item["PK"] = f"OIDC#{record['issuer']}"
        item["SK"] = "PROFILE"
        await self._execute_with_circuit_breaker(
            "save_oidc_provider",
            self.client.put_item,
            TableName=self._get_table_name("oidc_providers"),
            Item=self._serialize_item(item),
            ConditionExpression="attribute_not_exists(PK)",
        )
        return dict(record)

    async def get_oidc_provider(self, issuer_or_slug: str) -> Optional[Dict[str, Any]]:
        record = await self._get_record(
            self._get_table_name("oidc_providers"), f"OIDC#{issuer_or_slug}"
        )
        if record is not None:
            return record
        # Documented scan fallback: identifier is a slug.
        slug_items = await self._scan_all(
            self._get_table_name("oidc_providers"),
            filter_expression="slug = :slug",
            expression_attribute_values={
                ":slug": {"S": str(issuer_or_slug).lower()}
            },
        )
        if not slug_items:
            return None
        return self._record_from_item(self._deserialize_item(slug_items[0]))

    async def update_oidc_provider(
        self, identifier: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Whitelisted update; unknown keys raise ``ValueError``."""
        if not isinstance(updates, dict):
            raise ValueError("updates must be a dict")
        rejected = set(updates) - OIDC_UPDATABLE_FIELDS
        if rejected:
            raise ValueError(
                f"OIDC provider fields not updatable: {sorted(rejected)}"
            )
        existing = await self.get_oidc_provider(identifier)
        if existing is None:
            return None
        current_issuer = existing["issuer"]
        new_slug = updates.get("slug")
        if new_slug is not None and str(new_slug).lower() != existing.get("slug"):
            candidate = str(new_slug).lower()
            # Documented scan fallback for slug uniqueness.
            slug_items = await self._scan_all(
                self._get_table_name("oidc_providers"),
                filter_expression="slug = :slug",
                expression_attribute_values={":slug": {"S": candidate}},
            )
            for item in slug_items:
                record = self._record_from_item(self._deserialize_item(item))
                if record.get("issuer") != current_issuer:
                    raise IntegrityError(
                        f"An OIDC provider with slug {candidate!r} "
                        "already exists"
                    )
        set_fields = {
            key: value for key, value in updates.items() if key != "issuer"
        }
        if new_slug is not None:
            set_fields["slug"] = str(new_slug).lower()
        set_fields["updated_at"] = _iso(_utcnow())
        new_issuer = updates.get("issuer")
        if new_issuer is not None and str(new_issuer) != current_issuer:
            # Issuer is part of the PK: move the item (delete + conditional
            # put) instead of an in-place update.
            if await self._get_record(
                self._get_table_name("oidc_providers"), f"OIDC#{new_issuer}"
            ) is not None:
                raise IntegrityError(
                    f"An OIDC provider with issuer {new_issuer!r} "
                    "already exists"
                )
            updated = dict(existing)
            updated.update(updates)
            updated["issuer"] = str(new_issuer)
            if new_slug is not None:
                updated["slug"] = str(new_slug).lower()
            updated["updated_at"] = _iso(_utcnow())
            item = dict(updated)
            item["PK"] = f"OIDC#{updated['issuer']}"
            item["SK"] = "PROFILE"
            await self._execute_with_circuit_breaker(
                "update_oidc_provider",
                self.client.put_item,
                TableName=self._get_table_name("oidc_providers"),
                Item=self._serialize_item(item),
                ConditionExpression="attribute_not_exists(PK)",
            )
            await self._execute_with_circuit_breaker(
                "update_oidc_provider_move",
                self.client.delete_item,
                TableName=self._get_table_name("oidc_providers"),
                Key={
                    "PK": {"S": f"OIDC#{current_issuer}"},
                    "SK": {"S": "PROFILE"},
                },
            )
            return updated
        result = await self._update_record(
            self._get_table_name("oidc_providers"),
            f"OIDC#{current_issuer}",
            "PROFILE",
            set_fields,
            condition_expression="attribute_exists(PK)",
        )
        return result
